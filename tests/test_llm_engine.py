"""Tests for LLM engine."""

import pytest

from py_vuln_scout.engines.llm_engine import LLMEngine
from py_vuln_scout.output.findings import Engine


def test_llm_engine_detects_vulnerability(
    sample_code, sample_llm_rule, mock_ollama_client, mock_vulnerable_llm_response
):
    """Test that LLM engine detects vulnerabilities."""
    mock_ollama_client.generate.return_value = mock_vulnerable_llm_response
    mock_ollama_client.validate_json_response.return_value = {
        "vulnerable": True,
        "reason": "XSS vulnerability",
        "evidence": [
            {
                "line_start": 8,
                "line_end": 8,
                "snippet": 'request.args.get("name")',
                "source": "request.args.get",
                "sink": "render_template_string",
            }
        ],
        "confidence": 0.85,
        "type": "reflected-xss",
        "sanitization_absent": True,
        "proposed_payloads": ["<script>alert(1)</script>"],
    }

    engine = LLMEngine([sample_llm_rule], mock_ollama_client)
    findings = engine.analyze("test.py", sample_code)

    assert len(findings) > 0
    assert findings[0].cwe_id == "CWE-79"
    assert findings[0].engine == Engine.LLM
    assert findings[0].confidence > 0.5
    assert mock_ollama_client.generate.called


def test_llm_engine_safe_code(
    sample_llm_rule, mock_ollama_client, mock_safe_llm_response
):
    """Test that LLM engine doesn't flag safe code."""
    safe_code = """
from flask import Flask, request, render_template_string, escape

@app.route("/hello")
def hello():
    name = escape(request.args.get("name"))
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)
"""
    mock_ollama_client.generate.return_value = mock_safe_llm_response
    mock_ollama_client.validate_json_response.return_value = {
        "vulnerable": False,
        "reason": "Properly escaped",
        "evidence": [],
        "confidence": 0.9,
    }

    engine = LLMEngine([sample_llm_rule], mock_ollama_client)
    findings = engine.analyze("safe.py", safe_code)

    assert len(findings) == 0


def test_llm_engine_invalid_json_response(
    sample_code, sample_llm_rule, mock_ollama_client
):
    """Test that LLM engine handles invalid JSON gracefully."""
    mock_ollama_client.generate.return_value = "This is not JSON"
    mock_ollama_client.validate_json_response.return_value = None

    engine = LLMEngine([sample_llm_rule], mock_ollama_client)
    findings = engine.analyze("test.py", sample_code)

    # Should not crash, just return no findings
    assert len(findings) == 0


def test_llm_engine_ollama_error(sample_code, sample_llm_rule, mock_ollama_client):
    """Test that LLM engine handles Ollama errors gracefully."""
    from py_vuln_scout.llm.ollama_client import OllamaError

    mock_ollama_client.generate.side_effect = OllamaError("Connection failed")

    engine = LLMEngine([sample_llm_rule], mock_ollama_client)
    findings = engine.analyze("test.py", sample_code)

    # Should not crash, just return no findings
    assert len(findings) == 0


def test_llm_engine_metadata(
    sample_code, sample_llm_rule, mock_ollama_client, mock_vulnerable_llm_response
):
    """Test that LLM engine includes metadata."""
    mock_ollama_client.generate.return_value = mock_vulnerable_llm_response
    mock_ollama_client.validate_json_response.return_value = {
        "vulnerable": True,
        "reason": "XSS",
        "evidence": [
            {"line_start": 1, "line_end": 1, "snippet": "test"}
        ],
        "confidence": 0.85,
    }

    engine = LLMEngine([sample_llm_rule], mock_ollama_client)
    findings = engine.analyze("test.py", sample_code)

    assert len(findings) > 0
    assert findings[0].metadata.model_name == "qwen2.5-coder:7b"
    assert findings[0].metadata.latency_ms is not None
    assert findings[0].metadata.latency_ms > 0
