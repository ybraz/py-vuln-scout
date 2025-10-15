# py-vuln-scout Architecture

This document describes the internal architecture and design decisions of py-vuln-scout.

## Overview

py-vuln-scout is a modular SAST (Static Application Security Testing) tool that combines traditional regex-based pattern matching with LLM-powered semantic analysis to detect security vulnerabilities in Python code.

## Design Principles

1. **Modularity**: Each component (engine, analyzer, formatter) is independent and composable
2. **Extensibility**: Easy to add new CWEs, rules, and engines
3. **Privacy**: All LLM analysis happens locally via Ollama
4. **Validation**: All inputs validated against JSON schemas
5. **Testability**: Comprehensive mocking for external dependencies

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI (Typer)                          │
│                      cli.py, config.py                       │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    Analysis Pipeline                         │
├─────────────────────────────────────────────────────────────┤
│  1. Load Rules (JSON/YAML + Schema Validation)              │
│  2. Parse Code (AST + Taint Analysis)                       │
│  3. Run Engines (Regex → LLM → Validator → Explainer)       │
│  4. Merge & Filter Findings                                 │
│  5. Format Output (JSON/JSONL)                              │
└─────────────────────────────────────────────────────────────┘
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│ Regex Engine │  │  LLM Engine  │  │   Validator  │
│              │  │              │  │    Engine    │
│ • Pattern    │  │ • Semantic   │  │              │
│   Matching   │  │   Analysis   │  │ • PoC Gen    │
│ • AST        │  │ • Context    │  │ • Conflict   │
│   Anchoring  │  │   Aware      │  │   Resolution │
└──────────────┘  └──────┬───────┘  └──────────────┘
                         │
                         ▼
                  ┌──────────────┐
                  │  Explainer   │
                  │   Engine     │
                  │              │
                  │ • Risk       │
                  │ • Impact     │
                  │ • Fix        │
                  └──────────────┘
```

## Core Components

### 1. Engines (`src/py_vuln_scout/engines/`)

#### Regex Engine (`regex_engine.py`)

**Purpose**: Fast pattern-based detection with lightweight AST context.

**Process**:
1. Load regex patterns from rules
2. Apply patterns to code
3. Check AST context (required functions, sanitizers)
4. Adjust confidence based on context
5. Return findings with evidence

**Key Features**:
- PCRE-compatible regex patterns
- Flag support (IGNORECASE, MULTILINE, DOTALL, VERBOSE)
- AST anchoring for reducing false positives
- Confidence adjustment based on context

#### LLM Engine (`llm_engine.py`)

**Purpose**: Deep semantic analysis using local LLM.

**Process**:
1. Build context (code, AST, framework hints, sources/sinks)
2. Render detection prompt from template
3. Call Ollama API
4. Parse and validate JSON response
5. Extract evidence and create findings

**Key Features**:
- Template-based prompts (Jinja2)
- Strict JSON output validation
- Framework detection (Flask, Django, Jinja2)
- Configurable model parameters (temperature, max_tokens)
- Response caching for performance

#### Validator Engine (`validator_engine.py`)

**Purpose**: Resolve discrepancies between regex and LLM engines.

**Process**:
1. Detect disagreement (one found vuln, other didn't)
2. Generate PoC-focused prompt
3. Call LLM to assess plausibility
4. Adjust finding confidence based on result
5. Attach PoC information (payload, steps)

**Key Features**:
- Automatic discrepancy detection
- PoC generation without execution
- Confidence adjustment (±0.1 to ±0.2)
- Attack vector description

#### Explainer Engine (`explainer_engine.py`)

**Purpose**: Generate human-readable explanations.

**Process**:
1. Extract finding details
2. Render explanation prompt
3. Call LLM
4. Parse risk/impact/fix sections
5. Attach to finding

**Key Features**:
- Structured output (risk, impact[], fix[])
- Practical, actionable recommendations
- Code examples in fixes

### 2. Analysis Components (`src/py_vuln_scout/analysis/`)

#### AST Utils (`ast_utils.py`)

**Functions**:
- `parse_code()`: Parse Python source to AST
- `find_function_calls()`: Extract all function/method calls
- `extract_snippet()`: Get code snippet for line range
- `ast_to_json()`: Convert AST to JSON (limited depth)
- `get_line_range()`: Get line numbers from AST node

#### Taint Primitives (`taint_primitives.py`)

**Data**:
- `XSS_SOURCES`: User input sources (request.args, request.form, etc.)
- `XSS_SINKS`: Dangerous output functions (render_template_string, mark_safe, etc.)
- `XSS_SANITIZERS`: Safe functions (escape, |e filter, etc.)
- `FRAMEWORK_INDICATORS`: Framework detection patterns

**Functions**:
- `get_sources_for_cwe()`: Get sources by CWE ID
- `get_sinks_for_cwe()`: Get sinks by CWE ID
- `get_sanitizers_for_cwe()`: Get sanitizers by CWE ID
- `detect_framework()`: Identify frameworks in code

#### Fingerprint (`fingerprint.py`)

**Purpose**: Generate stable hashes for code snippets to detect duplicates.

**Process**:
1. Normalize code (remove comments, whitespace)
2. Create composite (file path + lines + code)
3. SHA256 hash
4. Return `sha256:hexdigest`

### 3. LLM Integration (`src/py_vuln_scout/llm/`)

#### Ollama Client (`ollama_client.py`)

**Features**:
- HTTP client for Ollama API (`/api/generate`)
- Exponential backoff retry logic
- Timeout handling (default 120s)
- Response caching via DiskCache
- JSON validation and extraction

**Methods**:
- `generate()`: Generate completion
- `validate_json_response()`: Parse and validate JSON

#### Prompt Templates (`prompt_templates.py`)

**Templates**:
- `VALIDATOR_PROMPT_TEMPLATE`: PoC generation
- `EXPLAINER_PROMPT_TEMPLATE`: Risk/impact/fix explanation

**Functions**:
- `render_validator_prompt()`: Render validator prompt
- `render_explainer_prompt()`: Render explainer prompt

#### Disk Cache (`cache/disk_cache.py`)

**Purpose**: Cache LLM responses to improve performance.

**Features**:
- SHA256-based cache keys (prompt + model + temperature)
- JSON storage format
- Automatic cache directory creation
- Graceful failure (never crashes on I/O errors)

### 4. Output (`src/py_vuln_scout/output/`)

#### Findings (`findings.py`)

**Models** (Pydantic v2):
- `Finding`: Main vulnerability finding
- `Evidence`: Single piece of evidence
- `PoC`: Proof-of-concept information
- `Explanation`: Risk/impact/fix description
- `Metadata`: Fingerprint, model, latency

**Enums**:
- `Severity`: LOW, MEDIUM, HIGH, CRITICAL
- `Engine`: regex, llm, merged
- `ValidatorStatus`: skipped, confirmed, rejected, inconclusive

**Formatters**:
- `FindingFormatter.to_json()`: Pretty JSON array
- `FindingFormatter.to_jsonl()`: One finding per line
- `FindingFormatter.write_to_file()`: Write to disk

### 5. Configuration (`config.py`)

**Models**:
- `ModelConfig`: LLM settings
- `ThresholdConfig`: Detection thresholds
- `Config`: Main configuration

**Functions**:
- `load_config()`: Load TOML config
- `load_rule_file()`: Load and validate JSON/YAML rule
- `load_rules_for_cwe()`: Load all rules for a CWE

**Features**:
- TOML configuration files
- JSON Schema validation for rules
- Default values fallback
- Support for JSON and YAML rules

## Data Flow

### Finding Creation Flow

```
Code Input
    │
    ├──> Regex Engine ──> Raw Hits
    │                         │
    └──> LLM Engine ──────────┤
                              │
                              ▼
                        Merge Logic
                        (fingerprint dedup)
                              │
                              ▼
                      Discrepancy Check
                              │
                    Yes ◄─────┴─────► No
                     │                │
                     ▼                ▼
              Validator Engine    Skip Validator
                     │                │
                     └────────┬───────┘
                              │
                              ▼
                       Explainer Engine
                              │
                              ▼
                      Filter by Confidence
                              │
                              ▼
                      Format & Output
```

### Confidence Adjustment Flow

```
Base Confidence (from rule)
    │
    ├──> AST Context Check
    │    ├─ Has required functions? +0.1
    │    └─ Has sanitizers?         -0.15
    │
    ├──> Engine Agreement
    │    └─ Both detect?            +0.05
    │
    ├──> Validator Check
    │    ├─ Confirmed?              +0.1
    │    ├─ Rejected?               -0.2
    │    └─ Inconclusive?            0.0
    │
    └──> Final Confidence (clamped to 0.0-1.0)
```

## Rule System

### Rule Structure

Rules are defined in JSON/YAML and validated against schemas:

- **Regex Rules**: Pattern-based detection
  - Regular expression patterns
  - AST context requirements
  - Taint source/sink specifications

- **LLM Rules**: Semantic analysis
  - Jinja2 prompt templates
  - Expected output format (JSON schema)
  - Model parameters

### Rule Loading

1. Load rule file (JSON or YAML)
2. Validate against schema (`jsonschema`)
3. Check required fields
4. Store in memory for analysis

### Rule Extension

To add a new rule:
1. Create JSON file following schema
2. Place in `rules/cwe-XXX/` directory
3. Tool automatically loads on next run

## Performance Optimizations

1. **Caching**: LLM responses cached on disk (deterministic only)
2. **Lazy Loading**: Rules loaded only when needed
3. **AST Reuse**: AST parsed once, used by all engines
4. **Snippet Limiting**: Code truncated to 2000 chars for LLM
5. **Parallel Potential**: Architecture supports parallel file analysis (future)

## Error Handling

### Graceful Degradation

- **Invalid Regex**: Skip pattern, continue with others
- **LLM Failure**: Return no findings, don't crash
- **Invalid JSON**: Skip rule/response, continue
- **Cache Failure**: Continue without cache
- **Schema Validation**: Skip invalid rules

### Error Reporting

- ConfigError: Configuration/rule loading issues
- OllamaError: LLM API failures
- All exceptions caught at CLI level

## Testing Strategy

### Unit Tests

- Mock external dependencies (Ollama, file I/O)
- Test each engine independently
- Validate finding schemas
- Test confidence adjustments

### Integration Tests

- CLI command execution
- End-to-end analysis pipeline
- Output format validation

### Fixtures (`tests/conftest.py`)

- Sample code (vulnerable and safe)
- Sample rules (regex and LLM)
- Mock Ollama client
- Mock LLM responses

## Security Considerations

1. **Local LLM**: All analysis happens locally (no data leaves machine)
2. **No Code Execution**: Static analysis only, never executes code
3. **PoC Generation**: Plans attacks but never executes
4. **Schema Validation**: All inputs validated to prevent injection

## Future Enhancements

### Planned Features

1. **Multi-file Analysis**: Analyze entire projects
2. **Dataflow Analysis**: Track taint flow across functions
3. **Custom Formatters**: SARIF, HTML reports
4. **IDE Integration**: VSCode extension
5. **CI/CD Integration**: GitHub Actions, GitLab CI
6. **More CWEs**: SQL injection, command injection, etc.
7. **Configuration Profiles**: Pre-defined configs for frameworks

### Architecture Evolution

- **Plugin System**: External engines/formatters
- **Distributed Analysis**: Analyze large projects in parallel
- **Web UI**: Dashboard for results visualization
- **Historical Tracking**: Track findings over time

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines on adding engines, rules, and tests.

## Performance Benchmarks

Typical performance (single file):
- Regex Engine: 10-100ms
- LLM Engine: 1-5s (first run), 10-50ms (cached)
- Validator Engine: 1-3s
- Explainer Engine: 1-3s

Total: ~5-10s for full analysis with all engines (first run)
        ~100-500ms with caching

## Maintenance

### Regular Tasks

- Update taint sources/sinks as frameworks evolve
- Tune confidence thresholds based on feedback
- Update LLM prompts for better accuracy
- Add new CWE rules

### Monitoring

- False positive rate (should be <10%)
- False negative rate (should be <5%)
- Performance metrics (analysis time)
- Cache hit rate (should be >80% for repeated analysis)

---

For questions or clarifications, please open a GitHub issue or discussion.
