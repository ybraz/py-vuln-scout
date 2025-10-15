"""Tests for validator engine."""

import pytest

from py_vuln_scout.engines.validator_engine import ValidatorEngine
from py_vuln_scout.output.findings import (
    Engine,
    Evidence,
    Finding,
    Severity,
    ValidatorStatus,
    create_finding,
)


def test_validator_confirms_vulnerability(mock_ollama_client):
    """Test validator confirms a plausible vulnerability."""
    mock_ollama_client.generate.return_value = """{
        "is_plausible": true,
        "best_payload": "<script>alert(1)</script>",
        "attack_vector": "XSS via query parameter",
        "steps": ["curl 'http://localhost/?name=<script>alert(1)</script>'"],
        "confidence": 0.9
    }"""
    mock_ollama_client.validate_json_response.return_value = {
        "is_plausible": True,
        "best_payload": "<script>alert(1)</script>",
        "attack_vector": "XSS via query parameter",
        "steps": ["curl 'http://localhost/?name=<script>alert(1)</script>'"],
        "confidence": 0.9,
    }

    evidence = [Evidence(line_start=1, line_end=1, snippet="test")]
    finding = create_finding(
        cwe_id="CWE-79",
        rule_id="test",
        engine=Engine.MERGED,
        severity=Severity.HIGH,
        confidence=0.6,
        file_path="test.py",
        line_start=1,
        line_end=1,
        snippet="test",
        evidence=evidence,
    )

    validator = ValidatorEngine(mock_ollama_client)
    result = validator.validate(finding, "test code", "vulnerable", "vulnerable")

    assert result.validator_status == ValidatorStatus.CONFIRMED
    assert result.poc is not None
    assert result.poc.best_payload == "<script>alert(1)</script>"
    assert result.confidence > 0.6  # Should be increased


def test_validator_rejects_vulnerability(mock_ollama_client):
    """Test validator rejects an implausible vulnerability."""
    mock_ollama_client.generate.return_value = """{
        "is_plausible": false,
        "best_payload": null,
        "attack_vector": "Not exploitable",
        "steps": [],
        "confidence": 0.1
    }"""
    mock_ollama_client.validate_json_response.return_value = {
        "is_plausible": False,
        "best_payload": None,
        "attack_vector": "Not exploitable",
        "steps": [],
        "confidence": 0.1,
    }

    evidence = [Evidence(line_start=1, line_end=1, snippet="test")]
    finding = create_finding(
        cwe_id="CWE-79",
        rule_id="test",
        engine=Engine.MERGED,
        severity=Severity.HIGH,
        confidence=0.8,
        file_path="test.py",
        line_start=1,
        line_end=1,
        snippet="test",
        evidence=evidence,
    )

    validator = ValidatorEngine(mock_ollama_client)
    result = validator.validate(finding, "test code", "vulnerable", "safe")

    assert result.validator_status == ValidatorStatus.REJECTED
    assert result.confidence < 0.8  # Should be decreased


def test_validator_handles_invalid_response(mock_ollama_client):
    """Test validator handles invalid JSON response."""
    mock_ollama_client.generate.return_value = "invalid json"
    mock_ollama_client.validate_json_response.return_value = None

    evidence = [Evidence(line_start=1, line_end=1, snippet="test")]
    finding = create_finding(
        cwe_id="CWE-79",
        rule_id="test",
        engine=Engine.MERGED,
        severity=Severity.HIGH,
        confidence=0.7,
        file_path="test.py",
        line_start=1,
        line_end=1,
        snippet="test",
        evidence=evidence,
    )

    validator = ValidatorEngine(mock_ollama_client)
    result = validator.validate(finding, "test code", "vulnerable", "vulnerable")

    assert result.validator_status == ValidatorStatus.INCONCLUSIVE


def test_validator_should_validate_on_discrepancy():
    """Test should_validate detects discrepancies."""
    evidence = [Evidence(line_start=1, line_end=1, snippet="test")]
    regex_findings = [
        create_finding(
            cwe_id="CWE-79",
            rule_id="test",
            engine=Engine.REGEX,
            severity=Severity.HIGH,
            confidence=0.6,
            file_path="test.py",
            line_start=1,
            line_end=1,
            snippet="test",
            evidence=evidence,
        )
    ]
    llm_findings = []

    validator = ValidatorEngine(None)  # type: ignore
    assert validator.should_validate(regex_findings, llm_findings) is True


def test_validator_should_not_validate_on_agreement():
    """Test should_validate when engines agree."""
    evidence = [Evidence(line_start=1, line_end=1, snippet="test")]
    regex_findings = [
        create_finding(
            cwe_id="CWE-79",
            rule_id="test",
            engine=Engine.REGEX,
            severity=Severity.HIGH,
            confidence=0.6,
            file_path="test.py",
            line_start=1,
            line_end=1,
            snippet="test",
            evidence=evidence,
        )
    ]
    llm_findings = [
        create_finding(
            cwe_id="CWE-79",
            rule_id="test",
            engine=Engine.LLM,
            severity=Severity.HIGH,
            confidence=0.7,
            file_path="test.py",
            line_start=1,
            line_end=1,
            snippet="test",
            evidence=evidence,
        )
    ]

    validator = ValidatorEngine(None)  # type: ignore
    assert validator.should_validate(regex_findings, llm_findings) is False
