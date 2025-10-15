"""Finding models and output formatters."""

import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

import jsonschema
from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Engine(str, Enum):
    """Analysis engines."""

    REGEX = "regex"
    LLM = "llm"
    MERGED = "merged"


class ValidatorStatus(str, Enum):
    """Validator engine status."""

    SKIPPED = "skipped"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class Evidence(BaseModel):
    """Evidence for a finding."""

    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    snippet: str
    source: str | None = None
    sink: str | None = None


class PoC(BaseModel):
    """Proof-of-concept information."""

    best_payload: str | None = None
    attack_vector: str | None = None
    steps: list[str] = Field(default_factory=list)


class Explanation(BaseModel):
    """Human-readable explanation."""

    risk: str
    impact: list[str]
    fix: list[str]


class Timestamps(BaseModel):
    """Timestamps for the finding."""

    analyzed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class Metadata(BaseModel):
    """Additional metadata."""

    model_name: str | None = None
    latency_ms: float | None = None
    fingerprint: str | None = None


class Finding(BaseModel):
    """Vulnerability finding."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    cwe_id: str
    rule_id: str
    engine: Engine
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    file_path: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    snippet: str
    evidence: list[Evidence]
    validator_status: ValidatorStatus = ValidatorStatus.SKIPPED
    poc: PoC | None = None
    explanation: Explanation | None = None
    merge_reason: str | None = None
    timestamps: Timestamps = Field(default_factory=Timestamps)
    metadata: Metadata = Field(default_factory=Metadata)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return json.loads(self.model_dump_json())

    def validate_against_schema(self, schema_path: str) -> bool:
        """Validate finding against JSON schema.

        Args:
            schema_path: Path to finding schema

        Returns:
            True if valid

        Raises:
            jsonschema.ValidationError: If validation fails
        """
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)

        jsonschema.validate(instance=self.to_dict(), schema=schema)
        return True


class FindingFormatter:
    """Format findings for output."""

    @staticmethod
    def to_json(findings: list[Finding]) -> str:
        """Format findings as JSON array.

        Args:
            findings: List of findings

        Returns:
            JSON string
        """
        data = [f.to_dict() for f in findings]
        return json.dumps(data, indent=2)

    @staticmethod
    def to_jsonl(findings: list[Finding]) -> str:
        """Format findings as JSONL (one per line).

        Args:
            findings: List of findings

        Returns:
            JSONL string
        """
        lines = [json.dumps(f.to_dict()) for f in findings]
        return "\n".join(lines)

    @staticmethod
    def write_to_file(findings: list[Finding], output_path: str, format: str = "json") -> None:
        """Write findings to file.

        Args:
            findings: List of findings
            output_path: Output file path
            format: Output format ("json" or "jsonl")
        """
        if format == "json":
            content = FindingFormatter.to_json(findings)
        elif format == "jsonl":
            content = FindingFormatter.to_jsonl(findings)
        else:
            raise ValueError(f"Unsupported format: {format}")

        Path(output_path).write_text(content, encoding="utf-8")


def create_finding(
    cwe_id: str,
    rule_id: str,
    engine: Engine,
    severity: Severity,
    confidence: float,
    file_path: str,
    line_start: int,
    line_end: int,
    snippet: str,
    evidence: list[Evidence],
    fingerprint: str | None = None,
    model_name: str | None = None,
    latency_ms: float | None = None,
) -> Finding:
    """Create a new finding.

    Args:
        cwe_id: CWE identifier
        rule_id: Rule identifier
        engine: Analysis engine
        severity: Severity level
        confidence: Confidence score
        file_path: Path to analyzed file
        line_start: Starting line number
        line_end: Ending line number
        snippet: Code snippet
        evidence: List of evidence
        fingerprint: Code fingerprint (optional)
        model_name: LLM model name (optional)
        latency_ms: Analysis latency (optional)

    Returns:
        Finding object
    """
    metadata = Metadata(
        fingerprint=fingerprint,
        model_name=model_name,
        latency_ms=latency_ms,
    )

    return Finding(
        cwe_id=cwe_id,
        rule_id=rule_id,
        engine=engine,
        severity=severity,
        confidence=confidence,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        snippet=snippet,
        evidence=evidence,
        metadata=metadata,
    )
