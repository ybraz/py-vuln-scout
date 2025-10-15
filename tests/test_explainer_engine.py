"""Tests for explainer engine."""

import pytest

from py_vuln_scout.engines.explainer_engine import ExplainerEngine
from py_vuln_scout.output.findings import Engine, Evidence, Severity, create_finding


def test_explainer_generates_explanation(mock_ollama_client):
    """Test explainer generates full explanation."""
    mock_ollama_client.generate.return_value = """{
        "risk": "User input flows directly to HTML rendering without sanitization, allowing arbitrary JavaScript execution.",
        "impact": ["Session hijacking", "Cookie theft", "Phishing attacks"],
        "fix": [
            "Use Flask's escape() function: escape(request.args.get('name'))",
            "Use template variables with autoescape: {{ name }}",
            "Apply |e filter in Jinja2 templates"
        ]
    }"""
    mock_ollama_client.validate_json_response.return_value = {
        "risk": "User input flows directly to HTML rendering without sanitization, allowing arbitrary JavaScript execution.",
        "impact": ["Session hijacking", "Cookie theft", "Phishing attacks"],
        "fix": [
            "Use Flask's escape() function: escape(request.args.get('name'))",
            "Use template variables with autoescape: {{ name }}",
            "Apply |e filter in Jinja2 templates",
        ],
    }

    evidence = [Evidence(line_start=1, line_end=1, snippet="test")]
    finding = create_finding(
        cwe_id="CWE-79",
        rule_id="test",
        engine=Engine.REGEX,
        severity=Severity.HIGH,
        confidence=0.8,
        file_path="test.py",
        line_start=1,
        line_end=1,
        snippet="test",
        evidence=evidence,
    )

    explainer = ExplainerEngine(mock_ollama_client)
    result = explainer.explain(finding, "test code")

    assert result.explanation is not None
    assert "JavaScript" in result.explanation.risk
    assert len(result.explanation.impact) == 3
    assert len(result.explanation.fix) == 3


def test_explainer_handles_invalid_response(mock_ollama_client):
    """Test explainer handles invalid JSON response."""
    mock_ollama_client.generate.return_value = "invalid json"
    mock_ollama_client.validate_json_response.return_value = None

    evidence = [Evidence(line_start=1, line_end=1, snippet="test")]
    finding = create_finding(
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

    explainer = ExplainerEngine(mock_ollama_client)
    result = explainer.explain(finding, "test code")

    # Should not crash, explanation remains None
    assert result.explanation is None


def test_explainer_updates_latency(mock_ollama_client):
    """Test explainer updates latency metadata."""
    mock_ollama_client.generate.return_value = '{"risk": "test", "impact": [], "fix": []}'
    mock_ollama_client.validate_json_response.return_value = {
        "risk": "test",
        "impact": [],
        "fix": [],
    }

    evidence = [Evidence(line_start=1, line_end=1, snippet="test")]
    finding = create_finding(
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
        latency_ms=100.0,
    )

    explainer = ExplainerEngine(mock_ollama_client)
    result = explainer.explain(finding, "test code")

    # Latency should be updated (increased)
    assert result.metadata.latency_ms is not None
    assert result.metadata.latency_ms > 100.0
