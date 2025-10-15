"""Tests for finding schema validation."""

import json
import uuid
from pathlib import Path

import jsonschema
import pytest

from py_vuln_scout.output.findings import (
    Engine,
    Evidence,
    Explanation,
    Finding,
    FindingFormatter,
    Metadata,
    PoC,
    Severity,
    Timestamps,
    ValidatorStatus,
    create_finding,
)


def test_create_finding():
    """Test creating a valid finding."""
    evidence = [
        Evidence(line_start=10, line_end=12, snippet="test code", source="request.args")
    ]

    finding = create_finding(
        cwe_id="CWE-79",
        rule_id="CWE-79.regex.001",
        engine=Engine.REGEX,
        severity=Severity.HIGH,
        confidence=0.75,
        file_path="test.py",
        line_start=10,
        line_end=12,
        snippet="test code",
        evidence=evidence,
        fingerprint="sha256:abc123",
    )

    assert finding.cwe_id == "CWE-79"
    assert finding.rule_id == "CWE-79.regex.001"
    assert finding.engine == Engine.REGEX
    assert finding.severity == Severity.HIGH
    assert finding.confidence == 0.75
    assert len(finding.evidence) == 1
    assert finding.metadata.fingerprint == "sha256:abc123"


def test_finding_to_dict():
    """Test converting finding to dictionary."""
    evidence = [Evidence(line_start=1, line_end=1, snippet="test")]
    finding = create_finding(
        cwe_id="CWE-79",
        rule_id="test",
        engine=Engine.REGEX,
        severity=Severity.HIGH,
        confidence=0.5,
        file_path="test.py",
        line_start=1,
        line_end=1,
        snippet="test",
        evidence=evidence,
    )

    data = finding.to_dict()
    assert isinstance(data, dict)
    assert data["cwe_id"] == "CWE-79"
    assert data["engine"] == "regex"


def test_finding_with_poc():
    """Test finding with PoC information."""
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

    finding.poc = PoC(
        best_payload="<script>alert(1)</script>",
        attack_vector="XSS via query parameter",
        steps=["curl http://localhost/?q=<script>alert(1)</script>"],
    )
    finding.validator_status = ValidatorStatus.CONFIRMED

    data = finding.to_dict()
    assert data["poc"]["best_payload"] == "<script>alert(1)</script>"
    assert data["validator_status"] == "confirmed"


def test_finding_with_explanation():
    """Test finding with explanation."""
    evidence = [Evidence(line_start=1, line_end=1, snippet="test")]
    finding = create_finding(
        cwe_id="CWE-79",
        rule_id="test",
        engine=Engine.LLM,
        severity=Severity.HIGH,
        confidence=0.9,
        file_path="test.py",
        line_start=1,
        line_end=1,
        snippet="test",
        evidence=evidence,
    )

    finding.explanation = Explanation(
        risk="User input is reflected without escaping",
        impact=["Session hijacking", "Data theft"],
        fix=["Use escape() function", "Enable autoescape in templates"],
    )

    data = finding.to_dict()
    assert len(data["explanation"]["impact"]) == 2
    assert len(data["explanation"]["fix"]) == 2


def test_finding_formatter_json():
    """Test JSON formatter."""
    evidence = [Evidence(line_start=1, line_end=1, snippet="test")]
    findings = [
        create_finding(
            cwe_id="CWE-79",
            rule_id="test",
            engine=Engine.REGEX,
            severity=Severity.HIGH,
            confidence=0.5,
            file_path="test.py",
            line_start=1,
            line_end=1,
            snippet="test",
            evidence=evidence,
        )
    ]

    output = FindingFormatter.to_json(findings)
    assert isinstance(output, str)

    # Validate it's proper JSON
    parsed = json.loads(output)
    assert isinstance(parsed, list)
    assert len(parsed) == 1


def test_finding_formatter_jsonl():
    """Test JSONL formatter."""
    evidence = [Evidence(line_start=1, line_end=1, snippet="test")]
    findings = [
        create_finding(
            cwe_id="CWE-79",
            rule_id="test1",
            engine=Engine.REGEX,
            severity=Severity.HIGH,
            confidence=0.5,
            file_path="test.py",
            line_start=1,
            line_end=1,
            snippet="test",
            evidence=evidence,
        ),
        create_finding(
            cwe_id="CWE-79",
            rule_id="test2",
            engine=Engine.LLM,
            severity=Severity.MEDIUM,
            confidence=0.6,
            file_path="test.py",
            line_start=2,
            line_end=2,
            snippet="test2",
            evidence=evidence,
        ),
    ]

    output = FindingFormatter.to_jsonl(findings)
    lines = output.strip().split("\n")
    assert len(lines) == 2

    # Each line should be valid JSON
    for line in lines:
        parsed = json.loads(line)
        assert isinstance(parsed, dict)


def test_finding_validates_against_schema():
    """Test that finding validates against JSON schema."""
    schema_path = Path(__file__).parent.parent / "src/py_vuln_scout/output/schemas/finding.schema.json"

    if not schema_path.exists():
        pytest.skip("Schema file not found")

    evidence = [Evidence(line_start=1, line_end=1, snippet="test")]
    finding = create_finding(
        cwe_id="CWE-79",
        rule_id="CWE-79.regex.001",
        engine=Engine.REGEX,
        severity=Severity.HIGH,
        confidence=0.75,
        file_path="test.py",
        line_start=1,
        line_end=1,
        snippet="test",
        evidence=evidence,
    )

    # Should not raise exception
    assert finding.validate_against_schema(str(schema_path))


def test_finding_uuid_format():
    """Test that finding ID is valid UUID."""
    evidence = [Evidence(line_start=1, line_end=1, snippet="test")]
    finding = create_finding(
        cwe_id="CWE-79",
        rule_id="test",
        engine=Engine.REGEX,
        severity=Severity.HIGH,
        confidence=0.5,
        file_path="test.py",
        line_start=1,
        line_end=1,
        snippet="test",
        evidence=evidence,
    )

    # Should be valid UUID v4
    uuid.UUID(finding.id, version=4)


def test_finding_timestamp_format():
    """Test that timestamp is in ISO8601 format."""
    evidence = [Evidence(line_start=1, line_end=1, snippet="test")]
    finding = create_finding(
        cwe_id="CWE-79",
        rule_id="test",
        engine=Engine.REGEX,
        severity=Severity.HIGH,
        confidence=0.5,
        file_path="test.py",
        line_start=1,
        line_end=1,
        snippet="test",
        evidence=evidence,
    )

    # Should contain ISO8601 timestamp
    assert "T" in finding.timestamps.analyzed_at
    assert ":" in finding.timestamps.analyzed_at
