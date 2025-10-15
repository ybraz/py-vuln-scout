"""LLM-based vulnerability detection engine."""

import json
import time
from typing import Any

from jinja2 import Template

from py_vuln_scout.analysis import ast_utils, fingerprint, taint_primitives
from py_vuln_scout.llm.ollama_client import OllamaClient, OllamaError
from py_vuln_scout.output.findings import Engine, Evidence, Finding, Severity, create_finding


class LLMEngine:
    """LLM-based detection engine using Ollama."""

    def __init__(
        self,
        rules: list[dict[str, Any]],
        client: OllamaClient,
    ) -> None:
        """Initialize LLM engine.

        Args:
            rules: List of LLM rules
            client: Ollama client instance
        """
        self.rules = rules
        self.client = client

    def analyze(self, file_path: str, code: str) -> list[Finding]:
        """Analyze code using LLM.

        Args:
            file_path: Path to analyzed file
            code: Python source code

        Returns:
            List of findings
        """
        findings = []

        for rule in self.rules:
            try:
                start_time = time.time()
                finding = self._apply_rule(rule, file_path, code)
                latency_ms = (time.time() - start_time) * 1000

                if finding:
                    finding.metadata.latency_ms = latency_ms
                    findings.append(finding)

            except OllamaError:
                # Skip rule if LLM call fails
                continue

        return findings

    def _apply_rule(
        self, rule: dict[str, Any], file_path: str, code: str
    ) -> Finding | None:
        """Apply a single LLM rule to code.

        Args:
            rule: Rule dictionary
            file_path: Path to analyzed file
            code: Python source code

        Returns:
            Finding if vulnerability detected, None otherwise
        """
        rule_id = rule["id"]
        cwe_id = rule["cwe_id"]

        # Build context
        tree = ast_utils.parse_code(code)
        ast_json = ast_utils.ast_to_json(tree) if tree else {}
        frameworks = taint_primitives.detect_framework(code)
        sources = taint_primitives.get_sources_for_cwe(cwe_id)
        sinks = taint_primitives.get_sinks_for_cwe(cwe_id)

        # Render prompt
        prompt_template = Template(rule["detection_prompt_template"])
        prompt = prompt_template.render(
            file_path=file_path,
            code=code[:2000],  # Limit code length
            ast_json=json.dumps(ast_json)[:1000],  # Limit AST size
            hints=", ".join(frameworks) if frameworks else "Unknown",
            sources=", ".join(sources[:5]),  # Top 5 sources
            sinks=", ".join(sinks[:5]),  # Top 5 sinks
            max_tokens=rule.get("model_params", {}).get("max_output_tokens", 512),
        )

        # Call LLM
        model_params = rule.get("model_params", {})
        temperature = model_params.get("temperature", 0.0)
        max_tokens = model_params.get("max_output_tokens", 512)

        response = self.client.generate(
            prompt=prompt,
            temperature=temperature,
            max_tokens=max_tokens,
        )

        # Parse and validate response
        parsed = self.client.validate_json_response(response)
        if not parsed or not self._validate_evidence_format(parsed, rule):
            return None

        # Check if vulnerability detected
        if not parsed.get("vulnerable", False):
            return None

        # Extract data from response
        confidence = parsed.get("confidence", 0.5)
        reason = parsed.get("reason", "")
        evidence_data = parsed.get("evidence", [])
        vuln_type = parsed.get("type", "unknown")

        # Create evidence objects
        evidence = []
        for ev in evidence_data:
            evidence.append(
                Evidence(
                    line_start=ev.get("line_start", 1),
                    line_end=ev.get("line_end", 1),
                    snippet=ev.get("snippet", ""),
                    source=ev.get("source"),
                    sink=ev.get("sink"),
                )
            )

        # Use first evidence for main snippet, or fallback
        if evidence:
            line_start = evidence[0].line_start
            line_end = evidence[0].line_end
            snippet = ast_utils.extract_snippet(code, line_start, line_end)
        else:
            line_start = 1
            line_end = min(10, len(code.splitlines()))
            snippet = ast_utils.extract_snippet(code, line_start, line_end)

        # Generate fingerprint (function-based)
        fp = fingerprint.generate_fingerprint(file_path, line_start, line_end, snippet, full_code=code)

        # Determine severity (default to HIGH for XSS)
        severity = Severity.HIGH if cwe_id == "CWE-79" else Severity.MEDIUM

        # Create finding
        finding = create_finding(
            cwe_id=cwe_id,
            rule_id=rule_id,
            engine=Engine.LLM,
            severity=severity,
            confidence=confidence,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            snippet=snippet,
            evidence=evidence,
            fingerprint=fp,
            model_name=self.client.model,
        )

        return finding

    def _validate_evidence_format(
        self, parsed: dict[str, Any], rule: dict[str, Any]
    ) -> bool:
        """Validate that LLM response matches expected evidence format.

        Args:
            parsed: Parsed JSON response
            rule: Rule dictionary

        Returns:
            True if valid
        """
        evidence_format = rule.get("evidence_format", {})
        required_fields = [k for k, v in evidence_format.items() if "required" in str(v)]

        # Check for required top-level fields
        for field in ["vulnerable", "reason", "evidence", "confidence"]:
            if field not in parsed:
                return False

        return True
