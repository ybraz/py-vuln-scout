"""Tests for the merger module."""

import pytest

from py_vuln_scout.engines.merger import merge_findings
from py_vuln_scout.output.findings import (
    Engine,
    Evidence,
    Finding,
    Metadata,
    Severity,
    ValidatorStatus,
)


@pytest.fixture
def sample_regex_finding():
    """Create a sample regex finding."""
    return Finding(
        cwe_id="CWE-79",
        rule_id="CWE-79.regex.001",
        engine=Engine.REGEX,
        severity=Severity.HIGH,
        confidence=0.7,
        file_path="test.py",
        line_start=10,
        line_end=10,
        snippet='return render_template_string("<h1>" + name + "</h1>")',
        evidence=[
            Evidence(
                line_start=10,
                line_end=10,
                snippet="render_template_string",
                source="request.args.get",
                sink="render_template_string",
            )
        ],
        metadata=Metadata(fingerprint="sha256:abc123"),
    )


@pytest.fixture
def sample_llm_finding():
    """Create a sample LLM finding."""
    return Finding(
        cwe_id="CWE-79",
        rule_id="CWE-79.llm.001",
        engine=Engine.LLM,
        severity=Severity.HIGH,
        confidence=0.85,
        file_path="test.py",
        line_start=10,
        line_end=10,
        snippet='return render_template_string("<h1>" + name + "</h1>")',
        evidence=[
            Evidence(
                line_start=10,
                line_end=10,
                snippet='render_template_string("<h1>" + name + "</h1>")',
                source="request.args.get",
                sink="render_template_string",
            )
        ],
        metadata=Metadata(fingerprint="sha256:abc123"),
    )


@pytest.fixture
def sample_regex_finding_different():
    """Create a different regex finding."""
    return Finding(
        cwe_id="CWE-79",
        rule_id="CWE-79.regex.001",
        engine=Engine.REGEX,
        severity=Severity.HIGH,
        confidence=0.6,
        file_path="test.py",
        line_start=20,
        line_end=20,
        snippet='return HttpResponse("<p>" + content + "</p>")',
        evidence=[
            Evidence(
                line_start=20,
                line_end=20,
                snippet="HttpResponse",
                source="request.POST.get",
                sink="HttpResponse",
            )
        ],
        metadata=Metadata(fingerprint="sha256:def456"),
    )


def test_merge_regex_llm_agreement(sample_regex_finding, sample_llm_finding):
    """Test merging when regex and LLM agree on the same finding."""
    result = merge_findings(
        regex_results=[sample_regex_finding],
        llm_results=[sample_llm_finding],
        validator_results=None,
        merged_only=True,
    )

    assert len(result) == 1
    assert result[0].engine == Engine.MERGED
    assert result[0].merge_reason == "regex_llm_agreement"
    assert result[0].confidence > sample_regex_finding.confidence
    assert result[0].confidence > 0.7  # Should have bonus


def test_merge_regex_only_validator_confirmed(sample_regex_finding):
    """Test regex-only finding that validator confirms."""
    # Set validator status to confirmed
    sample_regex_finding.validator_status = ValidatorStatus.CONFIRMED

    result = merge_findings(
        regex_results=[sample_regex_finding],
        llm_results=[],
        validator_results=[sample_regex_finding],
        merged_only=True,
    )

    assert len(result) == 1
    assert result[0].validator_status == ValidatorStatus.CONFIRMED
    assert result[0].merge_reason == "validator_confirmed"


def test_merge_regex_only_validator_rejected(sample_regex_finding):
    """Test regex-only finding that validator rejects (should be discarded)."""
    # Set validator status to rejected
    sample_regex_finding.validator_status = ValidatorStatus.REJECTED

    result = merge_findings(
        regex_results=[sample_regex_finding],
        llm_results=[],
        validator_results=[sample_regex_finding],
        merged_only=True,
    )

    # Should be discarded
    assert len(result) == 0


def test_merge_regex_only_validator_skipped(sample_regex_finding):
    """Test regex-only finding with validator not run (should be discarded)."""
    # Validator didn't run (validator_results=None)
    sample_regex_finding.validator_status = ValidatorStatus.SKIPPED

    result = merge_findings(
        regex_results=[sample_regex_finding],
        llm_results=[],
        validator_results=None,  # Validator didn't run
        merged_only=True,
    )

    # Should be discarded: no consensus, no validator confirmation
    # This is the strict mode - only merged or validator-confirmed findings appear
    assert len(result) == 0


def test_merge_regex_only_validator_ran_but_skipped(sample_regex_finding):
    """Test regex-only finding where validator ran but skipped (should be discarded)."""
    # Validator ran but skipped this finding
    sample_regex_finding.validator_status = ValidatorStatus.SKIPPED

    result = merge_findings(
        regex_results=[sample_regex_finding],
        llm_results=[],
        validator_results=[sample_regex_finding],  # Validator ran
        merged_only=True,
    )

    # Should be discarded because validator ran but skipped
    assert len(result) == 0


def test_merge_llm_only_validator_confirmed(sample_llm_finding):
    """Test LLM-only finding that validator confirms."""
    # Set validator status to confirmed
    sample_llm_finding.validator_status = ValidatorStatus.CONFIRMED

    result = merge_findings(
        regex_results=[],
        llm_results=[sample_llm_finding],
        validator_results=[sample_llm_finding],
        merged_only=True,
    )

    assert len(result) == 1
    assert result[0].validator_status == ValidatorStatus.CONFIRMED
    assert result[0].merge_reason == "validator_confirmed"


def test_merge_both_engines_different_locations(
    sample_regex_finding, sample_regex_finding_different
):
    """Test merging when engines detect different locations."""
    # Create LLM finding for different location
    llm_different = Finding(
        cwe_id="CWE-79",
        rule_id="CWE-79.llm.001",
        engine=Engine.LLM,
        severity=Severity.HIGH,
        confidence=0.8,
        file_path="test.py",
        line_start=30,
        line_end=30,
        snippet='return f"<div>{data}</div>"',
        evidence=[
            Evidence(
                line_start=30,
                line_end=30,
                snippet='f"<div>{data}</div>"',
                source="request.values.get",
                sink="f-string",
            )
        ],
        metadata=Metadata(fingerprint="sha256:ghi789"),
    )

    # Set validator confirmation for one
    sample_regex_finding_different.validator_status = ValidatorStatus.CONFIRMED

    result = merge_findings(
        regex_results=[sample_regex_finding, sample_regex_finding_different],
        llm_results=[llm_different],
        validator_results=[sample_regex_finding_different, llm_different],
        merged_only=True,
    )

    # Should only get the confirmed findings (not the one without agreement or confirmation)
    assert len(result) >= 1
    # Check that confirmed findings are included
    confirmed_ids = [f.metadata.fingerprint for f in result if f.validator_status == ValidatorStatus.CONFIRMED]
    assert "sha256:def456" in confirmed_ids or any(f.merge_reason == "validator_confirmed" for f in result)


def test_merge_no_merged_only_legacy_behavior(sample_regex_finding, sample_llm_finding):
    """Test legacy behavior when merged_only=False."""
    result = merge_findings(
        regex_results=[sample_regex_finding],
        llm_results=[sample_llm_finding],
        validator_results=None,
        merged_only=False,
    )

    # Legacy mode should return merged finding
    assert len(result) >= 1


def test_merge_empty_inputs():
    """Test merging with empty inputs."""
    result = merge_findings(
        regex_results=[],
        llm_results=[],
        validator_results=None,
        merged_only=True,
    )

    assert len(result) == 0


def test_merge_inconclusive_validator(sample_regex_finding):
    """Test handling of inconclusive validator status."""
    sample_regex_finding.validator_status = ValidatorStatus.INCONCLUSIVE

    result = merge_findings(
        regex_results=[sample_regex_finding],
        llm_results=[],
        validator_results=[sample_regex_finding],
        merged_only=True,
    )

    # Inconclusive should be discarded per rule 3
    assert len(result) == 0


def test_merge_preserves_explanation(sample_regex_finding, sample_llm_finding):
    """Test that explanation is preserved during merge."""
    from py_vuln_scout.output.findings import Explanation

    sample_llm_finding.explanation = Explanation(
        risk="XSS vulnerability",
        impact=["Session hijacking", "Data theft"],
        fix=["Use template variables", "Apply escape()"],
    )

    result = merge_findings(
        regex_results=[sample_regex_finding],
        llm_results=[sample_llm_finding],
        validator_results=None,
        merged_only=True,
    )

    assert len(result) == 1
    assert result[0].explanation is not None
    assert result[0].explanation.risk == "XSS vulnerability"
