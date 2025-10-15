"""Tests for configuration management."""

import json
from pathlib import Path

import pytest

from py_vuln_scout.config import (
    Config,
    ConfigError,
    load_config,
    load_rule_file,
    load_rules_for_cwe,
)


def test_load_default_config():
    """Test loading default config when file doesn't exist."""
    config = load_config("nonexistent.toml")
    assert isinstance(config, Config)
    assert config.model.name == "qwen2.5-coder:7b"
    assert config.model.base_url == "http://localhost:11434"
    assert config.thresholds.confidence_min == 0.35


def test_config_model():
    """Test config model validation."""
    config = Config()
    assert config.model.name == "qwen2.5-coder:7b"
    assert config.model.timeout == 120
    assert config.model.cache_enabled is True


def test_load_rule_file_json(tmp_path):
    """Test loading a JSON rule file."""
    # Create a test rule
    rule_data = {
        "id": "CWE-79.regex.001",
        "cwe_id": "CWE-79",
        "patterns": [{"regex": "test"}],
    }

    rule_file = tmp_path / "test_rule.json"
    rule_file.write_text(json.dumps(rule_data))

    # Create a minimal schema
    schema_data = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["id", "cwe_id", "patterns"],
        "properties": {
            "id": {"type": "string"},
            "cwe_id": {"type": "string"},
            "patterns": {"type": "array"},
        },
    }

    schema_file = tmp_path / "schema.json"
    schema_file.write_text(json.dumps(schema_data))

    # Load and validate
    rule = load_rule_file(str(rule_file), str(schema_file))
    assert rule["id"] == "CWE-79.regex.001"
    assert rule["cwe_id"] == "CWE-79"


def test_load_rule_file_invalid_json(tmp_path):
    """Test loading invalid JSON raises error."""
    rule_file = tmp_path / "invalid.json"
    rule_file.write_text("not json")

    schema_file = tmp_path / "schema.json"
    schema_file.write_text("{}")

    with pytest.raises(ConfigError):
        load_rule_file(str(rule_file), str(schema_file))


def test_load_rule_file_validation_failure(tmp_path):
    """Test schema validation failure."""
    # Rule missing required field
    rule_data = {"id": "test"}

    rule_file = tmp_path / "rule.json"
    rule_file.write_text(json.dumps(rule_data))

    schema_data = {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["id", "cwe_id"],
    }

    schema_file = tmp_path / "schema.json"
    schema_file.write_text(json.dumps(schema_data))

    with pytest.raises(ConfigError):
        load_rule_file(str(rule_file), str(schema_file))


def test_load_rules_for_cwe():
    """Test loading rules for a specific CWE."""
    # This will load the actual CWE-79 rules if they exist
    rules_dir = Path(__file__).parent.parent / "src/py_vuln_scout/rules"

    if not rules_dir.exists():
        pytest.skip("Rules directory not found")

    regex_rules = load_rules_for_cwe("CWE-79", str(rules_dir), "regex")
    llm_rules = load_rules_for_cwe("CWE-79", str(rules_dir), "llm")

    # Should find at least one of each type
    assert len(regex_rules) > 0
    assert len(llm_rules) > 0


def test_load_rules_for_nonexistent_cwe():
    """Test loading rules for non-existent CWE returns empty list."""
    rules_dir = Path(__file__).parent.parent / "src/py_vuln_scout/rules"

    rules = load_rules_for_cwe("CWE-9999", str(rules_dir), "regex")
    assert rules == []


def test_config_error_exception():
    """Test ConfigError exception."""
    with pytest.raises(ConfigError):
        raise ConfigError("Test error")
