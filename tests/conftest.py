"""Pytest configuration and fixtures."""

import pytest

from py_vuln_scout.llm.ollama_client import OllamaClient


@pytest.fixture
def sample_code():
    """Sample vulnerable Flask code."""
    return '''
from flask import Flask, request, render_template_string

app = Flask(__name__)

@app.route("/hello")
def hello():
    name = request.args.get("name", "Guest")
    return render_template_string("<h1>Hello " + name + "</h1>")
'''


@pytest.fixture
def sample_regex_rule():
    """Sample regex rule for testing."""
    return {
        "id": "CWE-79.regex.001",
        "name": "Test XSS Rule",
        "cwe_id": "CWE-79",
        "severity": "HIGH",
        "confidence": 0.6,
        "patterns": [
            {
                "regex": r"render_template_string\s*\([^)]*request\.(args|form)",
                "flags": ["MULTILINE"],
                "context": {
                    "require_call_names": ["render_template_string"],
                    "taint_sources": ["request.args"],
                    "taint_sinks": ["render_template_string"],
                },
            }
        ],
    }


@pytest.fixture
def sample_llm_rule():
    """Sample LLM rule for testing."""
    return {
        "id": "CWE-79.llm.001",
        "name": "Test LLM XSS Rule",
        "cwe_id": "CWE-79",
        "goal": "Detect XSS in Flask applications",
        "detection_prompt_template": "Analyze for XSS: {{code}}",
        "evidence_format": {
            "vulnerable": {"type": "boolean"},
            "reason": {"type": "string"},
            "evidence": {"type": "array"},
            "confidence": {"type": "number"},
        },
        "model_params": {"temperature": 0.0, "max_output_tokens": 512},
    }


@pytest.fixture
def mock_ollama_client(mocker):
    """Mock Ollama client."""
    client = mocker.Mock(spec=OllamaClient)
    client.model = "qwen2.5-coder:7b"
    return client


@pytest.fixture
def mock_vulnerable_llm_response():
    """Mock LLM response indicating vulnerability."""
    return """{
        "vulnerable": true,
        "reason": "User input flows to render_template_string without escaping",
        "evidence": [
            {
                "line_start": 8,
                "line_end": 8,
                "snippet": "request.args.get(\\"name\\")",
                "source": "request.args.get",
                "sink": "render_template_string"
            }
        ],
        "confidence": 0.85,
        "type": "reflected-xss",
        "sanitization_absent": true,
        "proposed_payloads": ["<script>alert(1)</script>"]
    }"""


@pytest.fixture
def mock_safe_llm_response():
    """Mock LLM response indicating no vulnerability."""
    return """{
        "vulnerable": false,
        "reason": "No direct user input in template rendering",
        "evidence": [],
        "confidence": 0.9,
        "type": "none",
        "sanitization_absent": false,
        "proposed_payloads": []
    }"""
