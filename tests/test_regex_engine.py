"""Tests for regex engine."""

import pytest

from py_vuln_scout.engines.regex_engine import RegexEngine
from py_vuln_scout.output.findings import Engine


def test_regex_engine_detects_vulnerability(sample_code, sample_regex_rule):
    """Test that regex engine detects vulnerable patterns."""
    engine = RegexEngine([sample_regex_rule])
    findings = engine.analyze("test.py", sample_code)

    assert len(findings) > 0
    assert findings[0].cwe_id == "CWE-79"
    assert findings[0].engine == Engine.REGEX
    assert findings[0].confidence > 0.0


def test_regex_engine_safe_code():
    """Test that regex engine doesn't flag safe code."""
    safe_code = '''
from flask import Flask, request, render_template_string, escape

@app.route("/hello")
def hello():
    name = escape(request.args.get("name", "Guest"))
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)
'''
    rule = {
        "id": "CWE-79.regex.001",
        "cwe_id": "CWE-79",
        "severity": "HIGH",
        "confidence": 0.6,
        "patterns": [
            {
                "regex": r"render_template_string\s*\([^)]*request\.(args|form)",
                "flags": [],
                "context": {"ban_sanitizers": ["escape"]},
            }
        ],
    }

    engine = RegexEngine([rule])
    findings = engine.analyze("safe.py", safe_code)

    # Should find it but with reduced confidence due to sanitizer
    if findings:
        assert findings[0].confidence < 0.6


def test_regex_engine_multiple_patterns(sample_code):
    """Test regex engine with multiple patterns."""
    rule = {
        "id": "CWE-79.regex.002",
        "cwe_id": "CWE-79",
        "severity": "HIGH",
        "confidence": 0.5,
        "patterns": [
            {"regex": r"render_template_string", "flags": []},
            {"regex": r"request\.args\.get", "flags": []},
        ],
    }

    engine = RegexEngine([rule])
    findings = engine.analyze("test.py", sample_code)

    # Should find both patterns
    assert len(findings) >= 2


def test_regex_engine_invalid_pattern():
    """Test that regex engine handles invalid patterns gracefully."""
    rule = {
        "id": "CWE-79.regex.003",
        "cwe_id": "CWE-79",
        "severity": "HIGH",
        "confidence": 0.5,
        "patterns": [
            {"regex": r"[invalid(regex", "flags": []},  # Invalid regex
        ],
    }

    engine = RegexEngine([rule])
    findings = engine.analyze("test.py", "some code")

    # Should not crash, just skip invalid pattern
    assert len(findings) == 0


def test_regex_engine_confidence_adjustment(sample_code):
    """Test confidence adjustment based on AST context."""
    rule = {
        "id": "CWE-79.regex.004",
        "cwe_id": "CWE-79",
        "severity": "HIGH",
        "confidence": 0.5,
        "patterns": [
            {
                "regex": r"render_template_string",
                "flags": [],
                "context": {
                    "require_call_names": ["render_template_string"],
                },
            }
        ],
    }

    engine = RegexEngine([rule])
    findings = engine.analyze("test.py", sample_code)

    # Confidence should be adjusted upward
    if findings:
        assert findings[0].confidence > 0.5
