"""Regex-based vulnerability detection engine."""

import re
from typing import Any

from py_vuln_scout.analysis import ast_utils, fingerprint
from py_vuln_scout.output.findings import Engine, Evidence, Finding, Severity, create_finding


class RegexHit:
    """Raw hit from regex pattern matching."""

    def __init__(
        self,
        rule_id: str,
        cwe_id: str,
        severity: Severity,
        confidence: float,
        file_path: str,
        line_start: int,
        line_end: int,
        snippet: str,
        evidence: list[Evidence],
    ) -> None:
        self.rule_id = rule_id
        self.cwe_id = cwe_id
        self.severity = severity
        self.confidence = confidence
        self.file_path = file_path
        self.line_start = line_start
        self.line_end = line_end
        self.snippet = snippet
        self.evidence = evidence


class RegexEngine:
    """Regex-based detection engine with AST anchoring."""

    def __init__(self, rules: list[dict[str, Any]]) -> None:
        """Initialize regex engine.

        Args:
            rules: List of regex rules
        """
        self.rules = rules

    def analyze(self, file_path: str, code: str) -> list[Finding]:
        """Analyze code using regex patterns.

        Args:
            file_path: Path to analyzed file
            code: Python source code

        Returns:
            List of findings
        """
        findings = []
        tree = ast_utils.parse_code(code)

        for rule in self.rules:
            hits = self._apply_rule(rule, file_path, code, tree)
            findings.extend(hits)

        return findings

    def _apply_rule(
        self, rule: dict[str, Any], file_path: str, code: str, tree: Any
    ) -> list[Finding]:
        """Apply a single rule to code.

        Args:
            rule: Rule dictionary
            file_path: Path to analyzed file
            code: Python source code
            tree: AST tree (or None if parsing failed)

        Returns:
            List of findings
        """
        findings = []
        rule_id = rule["id"]
        cwe_id = rule["cwe_id"]
        severity = Severity(rule.get("severity", "MEDIUM"))
        base_confidence = rule.get("confidence", 0.5)

        for pattern_spec in rule["patterns"]:
            pattern = pattern_spec["regex"]
            flags = pattern_spec.get("flags", [])
            context = pattern_spec.get("context", {})

            # Compile regex with flags
            regex_flags = 0
            if "IGNORECASE" in flags:
                regex_flags |= re.IGNORECASE
            if "MULTILINE" in flags:
                regex_flags |= re.MULTILINE
            if "DOTALL" in flags:
                regex_flags |= re.DOTALL
            if "VERBOSE" in flags:
                regex_flags |= re.VERBOSE

            try:
                regex = re.compile(pattern, regex_flags)
            except re.error:
                continue  # Skip invalid regex

            # Find matches
            for match in regex.finditer(code):
                # Calculate line numbers
                line_start = code[:match.start()].count("\n") + 1
                line_end = code[:match.end()].count("\n") + 1

                # Extract snippet
                snippet = ast_utils.extract_snippet(code, line_start, line_end)

                # Apply AST context checks and adjust confidence
                confidence = base_confidence
                if tree:
                    confidence = self._apply_ast_context(
                        tree, context, confidence, snippet
                    )

                # Create evidence
                evidence = [
                    Evidence(
                        line_start=line_start,
                        line_end=line_end,
                        snippet=match.group(0),
                    )
                ]

                # Generate fingerprint
                fp = fingerprint.generate_fingerprint(
                    file_path, line_start, line_end, snippet
                )

                # Create finding
                finding = create_finding(
                    cwe_id=cwe_id,
                    rule_id=rule_id,
                    engine=Engine.REGEX,
                    severity=severity,
                    confidence=confidence,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    snippet=snippet,
                    evidence=evidence,
                    fingerprint=fp,
                )

                findings.append(finding)

        return findings

    def _apply_ast_context(
        self, tree: Any, context: dict[str, Any], base_confidence: float, snippet: str
    ) -> float:
        """Apply AST context checks and adjust confidence.

        Args:
            tree: AST tree
            context: Context specification from rule
            base_confidence: Base confidence level
            snippet: Code snippet

        Returns:
            Adjusted confidence level
        """
        confidence = base_confidence

        # Get function calls from AST
        call_names = ast_utils.find_function_calls(tree)

        # Check required call names
        require_call_names = context.get("require_call_names", [])
        if require_call_names:
            has_required = any(
                req_call in snippet or req_call in call_names
                for req_call in require_call_names
            )
            if has_required:
                confidence += 0.1

        # Check for banned sanitizers (reduce confidence)
        ban_sanitizers = context.get("ban_sanitizers", [])
        if ban_sanitizers:
            has_sanitizer = any(
                san in snippet or san in call_names for san in ban_sanitizers
            )
            if has_sanitizer:
                confidence -= 0.15

        # Clamp confidence to [0, 1]
        return max(0.0, min(1.0, confidence))
