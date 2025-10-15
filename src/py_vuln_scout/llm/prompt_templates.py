"""Prompt templates for LLM engines."""

from jinja2 import Template


VALIDATOR_PROMPT_TEMPLATE = Template(
    """You are a penetration testing expert specializing in web application security.

A potential vulnerability has been identified with conflicting assessments from different detection engines.

File: {{file_path}}
CWE: {{cwe_id}}
Vulnerability Type: {{vuln_type}}

Code snippet:
```python
{{code}}
```

Detection conflict:
- Regex engine: {{regex_result}}
- LLM engine: {{llm_result}}

Your task:
1. Analyze if this is a PLAUSIBLE vulnerability that could be exploited
2. Generate a proof-of-concept exploit payload (without executing it)
3. Describe the attack vector and steps to reproduce

Return ONLY valid JSON (no additional text):
{
  "is_plausible": true/false,
  "best_payload": "exploit payload string",
  "attack_vector": "description of how the attack works",
  "steps": [
    "step 1: description",
    "step 2: curl command or similar",
    "step 3: expected result"
  ],
  "confidence": 0.0-1.0
}

Be conservative - only mark as plausible if you can construct a realistic attack scenario."""
)


EXPLAINER_PROMPT_TEMPLATE = Template(
    """You are a security expert explaining vulnerabilities to developers.

Vulnerability Details:
- CWE: {{cwe_id}}
- Type: {{vuln_type}}
- Severity: {{severity}}
- File: {{file_path}} (lines {{line_start}}-{{line_end}})

Code snippet:
```python
{{code}}
```

Evidence:
{{evidence}}

Provide a clear, actionable explanation for developers. Return ONLY valid JSON (no additional text):
{
  "risk": "2-4 sentence explanation of the security risk",
  "impact": [
    "Specific impact 1",
    "Specific impact 2",
    "Specific impact 3"
  ],
  "fix": [
    "Concrete fix step 1 with code example",
    "Concrete fix step 2 with code example",
    "Concrete fix step 3 with best practices"
  ]
}

Be specific, practical, and include code examples in the fix steps."""
)


def render_validator_prompt(
    file_path: str,
    cwe_id: str,
    vuln_type: str,
    code: str,
    regex_result: str,
    llm_result: str,
) -> str:
    """Render validator prompt.

    Args:
        file_path: Path to analyzed file
        cwe_id: CWE identifier
        vuln_type: Type of vulnerability
        code: Code snippet
        regex_result: Result from regex engine
        llm_result: Result from LLM engine

    Returns:
        Rendered prompt
    """
    return VALIDATOR_PROMPT_TEMPLATE.render(
        file_path=file_path,
        cwe_id=cwe_id,
        vuln_type=vuln_type,
        code=code,
        regex_result=regex_result,
        llm_result=llm_result,
    )


def render_explainer_prompt(
    cwe_id: str,
    vuln_type: str,
    severity: str,
    file_path: str,
    line_start: int,
    line_end: int,
    code: str,
    evidence: str,
) -> str:
    """Render explainer prompt.

    Args:
        cwe_id: CWE identifier
        vuln_type: Type of vulnerability
        severity: Severity level
        file_path: Path to analyzed file
        line_start: Starting line number
        line_end: Ending line number
        code: Code snippet
        evidence: Evidence description

    Returns:
        Rendered prompt
    """
    return EXPLAINER_PROMPT_TEMPLATE.render(
        cwe_id=cwe_id,
        vuln_type=vuln_type,
        severity=severity,
        file_path=file_path,
        line_start=line_start,
        line_end=line_end,
        code=code,
        evidence=evidence,
    )
