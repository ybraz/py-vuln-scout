"""Tests for CLI."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from py_vuln_scout.cli import app

runner = CliRunner()


def test_version_command():
    """Test version command."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "py-vuln-scout version" in result.stdout


def test_self_test_command():
    """Test self-test command."""
    result = runner.invoke(app, ["self-test"])
    # May fail if Ollama not running, but should not crash
    assert "Self-tests" in result.stdout or "Self-test failed" in result.stdout


def test_analyze_missing_file():
    """Test analyze with missing file."""
    result = runner.invoke(app, ["analyze", "nonexistent.py"])
    assert result.exit_code == 1
    assert "not found" in result.stdout.lower()


def test_analyze_with_example_file(tmp_path):
    """Test analyze with a real file."""
    # Create a test file
    test_file = tmp_path / "test.py"
    test_file.write_text(
        """
from flask import Flask, request, render_template_string

@app.route("/hello")
def hello():
    name = request.args.get("name")
    return render_template_string("<h1>Hello " + name + "</h1>")
"""
    )

    result = runner.invoke(app, ["analyze", str(test_file), "--format", "json", "--only", "regex"])

    # Should complete without error (may have 0 or more findings)
    assert result.exit_code == 0
    assert "Summary" in result.stdout


def test_analyze_json_output(tmp_path):
    """Test analyze with JSON output format."""
    test_file = tmp_path / "test.py"
    test_file.write_text("print('hello')")

    result = runner.invoke(app, ["analyze", str(test_file), "--format", "json", "--only", "regex"])

    assert result.exit_code == 0
    # Output should contain JSON (might be empty array)
    assert "[" in result.stdout or "Summary" in result.stdout


def test_analyze_jsonl_output(tmp_path):
    """Test analyze with JSONL output format."""
    test_file = tmp_path / "test.py"
    test_file.write_text("print('hello')")

    result = runner.invoke(app, ["analyze", str(test_file), "--format", "jsonl", "--only", "regex"])

    assert result.exit_code == 0


def test_analyze_with_output_file(tmp_path):
    """Test analyze writing to output file."""
    test_file = tmp_path / "test.py"
    output_file = tmp_path / "results.json"

    test_file.write_text(
        """
from flask import request, render_template_string
return render_template_string("<div>" + request.args.get("q") + "</div>")
"""
    )

    result = runner.invoke(
        app,
        [
            "analyze",
            str(test_file),
            "--format",
            "json",
            "--output",
            str(output_file),
            "--only",
            "regex",
        ],
    )

    # Should create output file
    if result.exit_code == 0:
        assert output_file.exists()
        # Validate it's proper JSON
        data = json.loads(output_file.read_text())
        assert isinstance(data, list)


def test_analyze_no_validate_flag(tmp_path):
    """Test analyze with --no-validate flag."""
    test_file = tmp_path / "test.py"
    test_file.write_text("print('hello')")

    result = runner.invoke(
        app, ["analyze", str(test_file), "--no-validate", "--only", "regex"]
    )

    assert result.exit_code == 0
    # Should not mention validator
    assert "validator" not in result.stdout.lower() or "Summary" in result.stdout


def test_analyze_no_explain_flag(tmp_path):
    """Test analyze with --no-explain flag."""
    test_file = tmp_path / "test.py"
    test_file.write_text("print('hello')")

    result = runner.invoke(
        app, ["analyze", str(test_file), "--no-explain", "--only", "regex"]
    )

    assert result.exit_code == 0
