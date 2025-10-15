"""Explainer engine for generating human-readable explanations."""

import time

from py_vuln_scout.llm.ollama_client import OllamaClient, OllamaError
from py_vuln_scout.llm.prompt_templates import render_explainer_prompt
from py_vuln_scout.output.findings import Explanation, Finding


class ExplainerEngine:
    """Explainer engine for generating risk/impact/fix descriptions."""

    def __init__(self, client: OllamaClient) -> None:
        """Initialize explainer engine.

        Args:
            client: Ollama client instance
        """
        self.client = client

    def explain(self, finding: Finding, code: str) -> Finding:
        """Generate explanation for a finding.

        Args:
            finding: Finding to explain
            code: Source code

        Returns:
            Updated finding with explanation
        """
        try:
            start_time = time.time()

            # Build evidence summary
            evidence_summary = "\n".join(
                [
                    f"- Line {ev.line_start}-{ev.line_end}: {ev.snippet[:50]}..."
                    for ev in finding.evidence
                ]
            )

            # Render prompt
            prompt = render_explainer_prompt(
                cwe_id=finding.cwe_id,
                vuln_type=finding.cwe_id,  # Simplification
                severity=finding.severity.value,
                file_path=finding.file_path,
                line_start=finding.line_start,
                line_end=finding.line_end,
                code=code,
                evidence=evidence_summary,
            )

            # Call LLM
            response = self.client.generate(
                prompt=prompt,
                temperature=0.0,
                max_tokens=512,
            )

            latency_ms = (time.time() - start_time) * 1000

            # Parse response
            parsed = self.client.validate_json_response(response)
            if parsed and "risk" in parsed:
                finding.explanation = Explanation(
                    risk=parsed.get("risk", ""),
                    impact=parsed.get("impact", []),
                    fix=parsed.get("fix", []),
                )

            # Update latency
            if finding.metadata.latency_ms:
                finding.metadata.latency_ms += latency_ms
            else:
                finding.metadata.latency_ms = latency_ms

        except OllamaError:
            # If explanation fails, leave it as None
            pass

        return finding
