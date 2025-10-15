"""Validator engine for resolving discrepancies between engines."""

import time
from typing import Any

from py_vuln_scout.llm.ollama_client import OllamaClient, OllamaError
from py_vuln_scout.llm.prompt_templates import render_validator_prompt
from py_vuln_scout.output.findings import Finding, PoC, ValidatorStatus


class ValidatorEngine:
    """Validator engine for generating PoCs and resolving discrepancies."""

    def __init__(self, client: OllamaClient) -> None:
        """Initialize validator engine.

        Args:
            client: Ollama client instance
        """
        self.client = client

    def validate(
        self,
        finding: Finding,
        code: str,
        regex_result: str,
        llm_result: str,
    ) -> Finding:
        """Validate a finding and generate PoC.

        Args:
            finding: Finding to validate
            code: Source code
            regex_result: Description of regex engine result
            llm_result: Description of LLM engine result

        Returns:
            Updated finding with validation results
        """
        try:
            start_time = time.time()

            # Render prompt
            prompt = render_validator_prompt(
                file_path=finding.file_path,
                cwe_id=finding.cwe_id,
                vuln_type=finding.cwe_id,  # Simplification
                code=code,
                regex_result=regex_result,
                llm_result=llm_result,
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
            if not parsed:
                finding.validator_status = ValidatorStatus.INCONCLUSIVE
                return finding

            # Extract validation results
            is_plausible = parsed.get("is_plausible", False)
            confidence_adjustment = 0.0

            if is_plausible:
                # Create PoC
                finding.poc = PoC(
                    best_payload=parsed.get("best_payload"),
                    attack_vector=parsed.get("attack_vector"),
                    steps=parsed.get("steps", []),
                )
                finding.validator_status = ValidatorStatus.CONFIRMED
                confidence_adjustment = 0.1
            else:
                finding.validator_status = ValidatorStatus.REJECTED
                confidence_adjustment = -0.2

            # Adjust confidence
            finding.confidence = max(0.0, min(1.0, finding.confidence + confidence_adjustment))

            # Update latency
            if finding.metadata.latency_ms:
                finding.metadata.latency_ms += latency_ms
            else:
                finding.metadata.latency_ms = latency_ms

        except OllamaError:
            finding.validator_status = ValidatorStatus.INCONCLUSIVE

        return finding

    def should_validate(self, regex_findings: list[Finding], llm_findings: list[Finding]) -> bool:
        """Determine if validation is needed due to discrepancy.

        Args:
            regex_findings: Findings from regex engine
            llm_findings: Findings from LLM engine

        Returns:
            True if there's a discrepancy
        """
        # Simple heuristic: if one found issues and the other didn't
        has_regex = len(regex_findings) > 0
        has_llm = len(llm_findings) > 0

        return has_regex != has_llm
