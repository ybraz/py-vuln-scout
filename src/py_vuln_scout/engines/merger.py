"""Merge findings from different engines with sophisticated logic."""

from typing import Optional

from py_vuln_scout.output.findings import Engine, Finding, ValidatorStatus


def merge_findings(
    regex_results: list[Finding],
    llm_results: list[Finding],
    validator_results: Optional[list[Finding]] = None,
    merged_only: bool = True,
) -> list[Finding]:
    """Merge findings from regex and LLM engines with validation logic.

    Rules:
    1. If regex and llm agree (same fingerprint) → finding appears with engine: "merged"
    2. If only one engine detects, but validator confirms → finding also appears
    3. If only one engine detects and no validator confirmation → finding is DISCARDED
    4. If validator explicitly rejects → finding is discarded
    5. If validator ran but skipped → finding is discarded
    6. validator_status and engine must clearly reflect final status: "merged", "confirmed", "rejected", "skipped"

    This strict approach ensures high precision by requiring either:
    - Consensus between engines (automatic merge), OR
    - Explicit validator confirmation

    Args:
        regex_results: Findings from regex engine
        llm_results: Findings from LLM engine
        validator_results: Findings after validation (optional, None means validator didn't run)
        merged_only: If True, only return merged/confirmed findings (default: True)

    Returns:
        List of merged findings according to the rules
    """
    if not merged_only:
        # Legacy mode: return all findings
        return _legacy_merge(regex_results, llm_results)

    # Build fingerprint maps for quick lookup
    regex_map = _build_fingerprint_map(regex_results)
    llm_map = _build_fingerprint_map(llm_results)

    # Create validator status map (indexed by finding id)
    validator_map = {}
    if validator_results:
        for finding in validator_results:
            validator_map[finding.id] = finding

    merged_findings = []
    processed_fingerprints = set()

    # Step 1: Find overlaps between regex and LLM (agreement)
    for fingerprint, regex_findings in regex_map.items():
        if fingerprint in llm_map and fingerprint not in processed_fingerprints:
            # Both engines detected this location - merge them
            llm_findings = llm_map[fingerprint]
            merged = _merge_agreed_findings(regex_findings, llm_findings)
            merged.merge_reason = "regex_llm_agreement"
            merged_findings.append(merged)
            processed_fingerprints.add(fingerprint)

    # Step 2: Handle regex-only findings
    for fingerprint, findings in regex_map.items():
        if fingerprint in processed_fingerprints:
            continue

        for finding in findings:
            # Check validator status
            validated = validator_map.get(finding.id, finding)

            if validated.validator_status == ValidatorStatus.CONFIRMED:
                # Validator confirmed this finding
                validated.merge_reason = "validator_confirmed"
                merged_findings.append(validated)
            # All other cases: discard (no consensus, no validator confirmation)
            # This includes: REJECTED, SKIPPED, INCONCLUSIVE

    # Step 3: Handle LLM-only findings
    for fingerprint, findings in llm_map.items():
        if fingerprint in processed_fingerprints:
            continue

        for finding in findings:
            # Check validator status
            validated = validator_map.get(finding.id, finding)

            if validated.validator_status == ValidatorStatus.CONFIRMED:
                # Validator confirmed this finding
                validated.merge_reason = "validator_confirmed"
                merged_findings.append(validated)
            # All other cases: discard (no consensus, no validator confirmation)
            # This includes: REJECTED, SKIPPED, INCONCLUSIVE

    return merged_findings


def _build_fingerprint_map(findings: list[Finding]) -> dict[str, list[Finding]]:
    """Build a map of fingerprint to findings.

    Args:
        findings: List of findings

    Returns:
        Dictionary mapping fingerprint to list of findings
    """
    fingerprint_map: dict[str, list[Finding]] = {}
    for finding in findings:
        fp = finding.metadata.fingerprint or f"{finding.line_start}:{finding.line_end}"
        if fp not in fingerprint_map:
            fingerprint_map[fp] = []
        fingerprint_map[fp].append(finding)
    return fingerprint_map


def _merge_agreed_findings(regex_findings: list[Finding], llm_findings: list[Finding]) -> Finding:
    """Merge findings where regex and LLM agree.

    Args:
        regex_findings: Findings from regex engine at this location
        llm_findings: Findings from LLM engine at this location

    Returns:
        Merged finding with engine="merged" and combined confidence
    """
    # Use the finding with highest confidence as base
    all_findings = regex_findings + llm_findings
    base = max(all_findings, key=lambda f: f.confidence)

    # Combine evidence from all findings
    all_evidence = []
    for finding in all_findings:
        all_evidence.extend(finding.evidence)

    # Remove duplicate evidence
    unique_evidence = []
    seen = set()
    for ev in all_evidence:
        key = (ev.line_start, ev.line_end, ev.snippet)
        if key not in seen:
            seen.add(key)
            unique_evidence.append(ev)

    # Create merged finding
    base.evidence = unique_evidence
    base.engine = Engine.MERGED
    base.confidence = min(1.0, base.confidence + 0.05)  # Small bonus for agreement

    # Preserve validator status if any finding has it
    for finding in all_findings:
        if finding.validator_status != ValidatorStatus.SKIPPED:
            base.validator_status = finding.validator_status
            if finding.poc:
                base.poc = finding.poc
            break

    # Preserve explanation from any finding that has it
    for finding in all_findings:
        if finding.explanation:
            base.explanation = finding.explanation
            break

    return base


def _legacy_merge(regex_findings: list[Finding], llm_findings: list[Finding]) -> list[Finding]:
    """Legacy merge: combine all findings without filtering.

    This is the original behavior when merged_only=False.

    Args:
        regex_findings: Findings from regex engine
        llm_findings: Findings from LLM engine

    Returns:
        Combined list of all findings
    """
    if not regex_findings:
        return llm_findings
    if not llm_findings:
        return regex_findings

    all_findings = []

    # Group by fingerprint
    fingerprint_map: dict[str, list[Finding]] = {}
    for finding in regex_findings + llm_findings:
        fp = finding.metadata.fingerprint or f"{finding.line_start}:{finding.line_end}"
        if fp not in fingerprint_map:
            fingerprint_map[fp] = []
        fingerprint_map[fp].append(finding)

    # Merge findings with same fingerprint
    for fp, findings in fingerprint_map.items():
        if len(findings) == 1:
            all_findings.append(findings[0])
        else:
            # Multiple findings with same fingerprint - merge them
            merged = _merge_duplicate_findings(findings)
            all_findings.append(merged)

    return all_findings


def _merge_duplicate_findings(findings: list[Finding]) -> Finding:
    """Merge multiple findings for the same location (legacy behavior).

    Args:
        findings: List of findings to merge

    Returns:
        Merged finding
    """
    # Use the finding with highest confidence as base
    base = max(findings, key=lambda f: f.confidence)

    # Combine evidence
    all_evidence = []
    for finding in findings:
        all_evidence.extend(finding.evidence)

    # Remove duplicate evidence
    unique_evidence = []
    seen = set()
    for ev in all_evidence:
        key = (ev.line_start, ev.line_end, ev.snippet)
        if key not in seen:
            seen.add(key)
            unique_evidence.append(ev)

    base.evidence = unique_evidence
    base.engine = Engine.MERGED
    base.confidence = min(1.0, base.confidence + 0.05)  # Small bonus for agreement

    return base
