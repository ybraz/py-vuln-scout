"""Configuration management for py-vuln-scout."""

import json
from pathlib import Path
from typing import Any

import jsonschema
import toml
import yaml
from pydantic import BaseModel, Field


class ModelConfig(BaseModel):
    """LLM model configuration."""

    name: str = Field(default="qwen2.5-coder:7b", description="Ollama model name")
    base_url: str = Field(default="http://localhost:11434", description="Ollama API base URL")
    timeout: int = Field(default=120, description="Request timeout in seconds")
    cache_enabled: bool = Field(default=True, description="Enable response caching")


class ThresholdConfig(BaseModel):
    """Detection threshold configuration."""

    confidence_min: float = Field(
        default=0.35, ge=0.0, le=1.0, description="Minimum confidence to report"
    )


class Config(BaseModel):
    """Main configuration."""

    model: ModelConfig = Field(default_factory=ModelConfig)
    rules_dir: str = Field(
        default="./src/py_vuln_scout/rules", description="Directory containing rule files"
    )
    thresholds: ThresholdConfig = Field(default_factory=ThresholdConfig)


def load_config(config_path: str | None = None) -> Config:
    """Load configuration from file.

    Args:
        config_path: Path to config file (TOML). If None, uses default.

    Returns:
        Configuration object
    """
    if config_path is None:
        config_path = "py-vuln-scout.toml"

    config_file = Path(config_path)

    if not config_file.exists():
        # Return default config
        return Config()

    try:
        data = toml.load(config_file)
        return Config(**data)
    except Exception as e:
        raise ConfigError(f"Failed to load config from {config_path}: {e}") from e


def load_rule_file(rule_path: str, schema_path: str) -> dict[str, Any]:
    """Load and validate a rule file (JSON or YAML).

    Args:
        rule_path: Path to rule file
        schema_path: Path to JSON schema for validation

    Returns:
        Validated rule dictionary

    Raises:
        ConfigError: If rule file is invalid
    """
    rule_file = Path(rule_path)
    schema_file = Path(schema_path)

    if not rule_file.exists():
        raise ConfigError(f"Rule file not found: {rule_path}")

    if not schema_file.exists():
        raise ConfigError(f"Schema file not found: {schema_path}")

    # Load rule file
    try:
        if rule_file.suffix == ".json":
            with open(rule_file, "r", encoding="utf-8") as f:
                rule_data = json.load(f)
        elif rule_file.suffix in [".yaml", ".yml"]:
            with open(rule_file, "r", encoding="utf-8") as f:
                rule_data = yaml.safe_load(f)
        else:
            raise ConfigError(f"Unsupported rule file format: {rule_file.suffix}")
    except Exception as e:
        raise ConfigError(f"Failed to parse rule file {rule_path}: {e}") from e

    # Load schema
    try:
        with open(schema_file, "r", encoding="utf-8") as f:
            schema = json.load(f)
    except Exception as e:
        raise ConfigError(f"Failed to load schema {schema_path}: {e}") from e

    # Validate rule against schema
    try:
        jsonschema.validate(instance=rule_data, schema=schema)
    except jsonschema.ValidationError as e:
        raise ConfigError(f"Rule validation failed for {rule_path}: {e.message}") from e

    return rule_data


def load_rules_for_cwe(
    cwe_id: str, rules_dir: str, engine_type: str
) -> list[dict[str, Any]]:
    """Load all rules for a specific CWE and engine type.

    Args:
        cwe_id: CWE identifier (e.g., "CWE-79")
        rules_dir: Base rules directory
        engine_type: Engine type ("regex" or "llm")

    Returns:
        List of rule dictionaries
    """
    rules_base = Path(rules_dir)
    cwe_dir = rules_base / cwe_id.lower()

    if not cwe_dir.exists():
        return []

    # Determine schema path
    if engine_type == "regex":
        schema_path = rules_base / "schema" / "regex_rule.schema.json"
    elif engine_type == "llm":
        schema_path = rules_base / "schema" / "llm_rule.schema.json"
    else:
        raise ConfigError(f"Unknown engine type: {engine_type}")

    # Load rule files
    rules = []
    for rule_file in cwe_dir.glob(f"{engine_type}.*"):
        if rule_file.suffix in [".json", ".yaml", ".yml"]:
            try:
                rule = load_rule_file(str(rule_file), str(schema_path))
                rules.append(rule)
            except ConfigError:
                # Skip invalid rules but continue
                continue

    return rules


class ConfigError(Exception):
    """Exception raised for configuration errors."""

    pass
