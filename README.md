# py-vuln-scout

A modular Static Application Security Testing (SAST) tool for Python that combines regex-based pattern matching with LLM-powered analysis to detect security vulnerabilities.

## Features

- **Multi-Engine Analysis**: Combines regex and LLM-based detection for comprehensive coverage
- **Modular Architecture**: Four specialized engines working together:
  - **Regex Engine**: Fast pattern matching with AST context anchoring
  - **LLM Engine**: Deep semantic analysis using Ollama
  - **Validator Engine**: Generates PoCs to resolve discrepancies between engines
  - **Explainer Engine**: Provides actionable risk/impact/fix explanations
- **Customizable Rules**: JSON/YAML rule definitions with schema validation
- **Focus on XSS (CWE-79)**: Initial release targets Cross-Site Scripting in Flask/Django/Jinja2
- **Flexible Output**: JSON or JSONL format with rich metadata
- **Local LLM**: Uses Ollama for privacy-preserving analysis

## Requirements

- Python 3.11+
- [Ollama](https://ollama.ai/) running locally (for LLM-based features)

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/ybraz/py-vuln-scout.git
cd py-vuln-scout
```

### 2. Create a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install dependencies

```bash
make install-dev
# or
pip install -e ".[dev]"
```

### 4. Install and start Ollama

Download and install Ollama from [ollama.ai](https://ollama.ai/)

Pull the default model:

```bash
ollama pull qwen2.5-coder:7b
```

Verify Ollama is running:

```bash
curl http://localhost:11434/api/version
```

## Quick Start

### Analyze a Python file

```bash
pvs analyze examples/flask_xss.py --format jsonl
```

### Run with specific engine only

```bash
# Regex only (fast, no LLM required)
pvs analyze myapp.py --only regex

# LLM only (slower, more accurate)
pvs analyze myapp.py --only llm
```

### Save results to file

```bash
pvs analyze myapp.py --format json --output results.json
```

### Skip validator and explainer for faster analysis

```bash
pvs analyze myapp.py --no-validate --no-explain
```

## Configuration

Create a `py-vuln-scout.toml` file in your project directory:

```toml
[model]
name = "qwen2.5-coder:7b"
base_url = "http://localhost:11434"
timeout = 120
cache_enabled = true

rules_dir = "./src/py_vuln_scout/rules"

[thresholds]
confidence_min = 0.35
```

Or use command-line options:

```bash
pvs analyze myapp.py --model "codellama:13b" --rules-dir ./custom_rules
```

## How It Works

### Analysis Flow

1. **Regex Engine** scans code with pattern matching + AST anchoring
2. **LLM Engine** performs semantic analysis with context understanding
3. **Merge Logic** combines findings using function-based fingerprints:
   - Findings in the same function get the same fingerprint
   - When both engines detect → automatic merge with confidence boost
   - When only one engine detects → validator decides
4. **Validator Engine** (on discrepancies) generates PoCs to confirm/reject
5. **Explainer Engine** adds human-readable risk/impact/fix descriptions

### Confidence Scoring

- Base confidence from rule definition (0.0-1.0)
- Adjusted based on AST context:
  - `+0.1` if required functions present
  - `-0.15` if sanitizers detected
- `+0.05` bonus when engines agree (merged)
- `+0.1` if validator confirms
- `-0.2` if validator rejects

### Example Finding

```json
{
  "id": "b0b5b7f3-6a38-4a66-b4c1-9e0f4fbf0a77",
  "cwe_id": "CWE-79",
  "rule_id": "CWE-79.regex.001",
  "engine": "merged",
  "severity": "HIGH",
  "confidence": 0.78,
  "file_path": "app/views.py",
  "line_start": 42,
  "line_end": 50,
  "snippet": "return render_template_string('<div>'+ request.args.get('q') +'</div>')",
  "evidence": [
    {
      "line_start": 42,
      "line_end": 42,
      "snippet": "request.args.get('q')",
      "source": "request.args.get"
    }
  ],
  "validator_status": "confirmed",
  "merge_reason": "regex_llm_agreement",
  "poc": {
    "best_payload": "<img src=x onerror=alert(1)>",
    "steps": ["curl 'http://localhost:5000/search?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E'"]
  },
  "explanation": {
    "risk": "User input is reflected in HTML without escaping, allowing JavaScript execution.",
    "impact": ["Session hijacking", "Cookie theft", "Defacement"],
    "fix": [
      "Use template variables with autoescape: {{ name }}",
      "Apply escape() function: escape(request.args.get('q'))",
      "Use |e filter in Jinja2 templates"
    ]
  },
  "timestamps": {"analyzed_at": "2025-10-15T18:05:12Z"},
  "metadata": {
    "model_name": "qwen2.5-coder:7b",
    "latency_ms": 412,
    "fingerprint": "sha256:..."
  }
}
```

## Creating Custom Rules

### Regex Rules

Create a JSON file in `rules/cwe-XXX/regex.json`:

```json
{
  "id": "CWE-79.regex.002",
  "name": "Django mark_safe XSS",
  "cwe_id": "CWE-79",
  "severity": "HIGH",
  "confidence": 0.65,
  "patterns": [
    {
      "regex": "mark_safe\\([^)]*request\\.",
      "flags": ["MULTILINE"],
      "context": {
        "require_call_names": ["mark_safe"],
        "ban_sanitizers": ["escape"],
        "taint_sources": ["request.GET", "request.POST"],
        "taint_sinks": ["mark_safe"]
      }
    }
  ],
  "examples": {
    "positive": ["return mark_safe(request.GET.get('html'))"],
    "negative": ["return mark_safe(escape(request.GET.get('html')))"]
  }
}
```

### LLM Rules

Create a JSON file in `rules/cwe-XXX/llm.json`:

```json
{
  "id": "CWE-79.llm.002",
  "name": "LLM XSS Detection - Advanced",
  "cwe_id": "CWE-79",
  "goal": "Detect complex XSS patterns",
  "detection_prompt_template": "Analyze this Python code for XSS vulnerabilities...\n{{code}}",
  "evidence_format": {
    "vulnerable": {"type": "boolean"},
    "reason": {"type": "string"},
    "evidence": {"type": "array"},
    "confidence": {"type": "number"}
  },
  "model_params": {
    "temperature": 0.0,
    "max_output_tokens": 512
  }
}
```

### Validate Rules

Rules are automatically validated against JSON schemas on load. Schemas are in `src/py_vuln_scout/rules/schema/`.

## Development

### Run tests

```bash
make test
```

### Run linters

```bash
make lint
```

### Format code

```bash
make format
```

### Install pre-commit hooks

```bash
make pre-commit
```

## Supported Vulnerabilities

### Current (v0.1.0)

- **CWE-79**: Cross-Site Scripting (XSS) in Flask, Django, and Jinja2

### Roadmap

- CWE-89: SQL Injection
- CWE-78: OS Command Injection
- CWE-502: Deserialization of Untrusted Data
- CWE-22: Path Traversal
- Multi-file analysis support
- Dataflow analysis improvements

## Limitations

- Currently analyzes one file at a time
- Limited to CWE-79 (XSS) in initial release
- Requires Ollama running locally for LLM features
- May produce false positives (tune `confidence_min` threshold)

## CLI Reference

### Commands

- `pvs analyze <file>` - Analyze a Python file
- `pvs version` - Show version information
- `pvs self-test` - Run internal diagnostics

### Options for `analyze`

- `--format [json|jsonl]` - Output format (default: jsonl)
- `--rules-dir <path>` - Custom rules directory
- `--model <name>` - Override Ollama model
- `--only [regex|llm|both]` - Run specific engine(s)
- `--no-validate` - Skip validator engine
- `--no-explain` - Skip explainer engine
- `--merged-only` / `--no-merged-only` - Only show merged/confirmed findings (default: true)
- `--output <file>` - Write results to file
- `--config <path>` - Custom config file

### Merge Logic and Finding Filtering

By default (`--merged-only`), the tool applies sophisticated merge logic to reduce false positives:

1. **Consensus Mode**: Findings appear when regex and LLM agree (same fingerprint) → marked as `engine: "merged"` with `merge_reason: "regex_llm_agreement"`
2. **Validator Confirmation**: Single-engine findings appear if validator confirms them → `merge_reason: "validator_confirmed"` with `validator_status: "confirmed"`
3. **High Confidence**: When validator is disabled (`--no-validate`), findings with confidence ≥ 0.7 are kept
4. **Rejection**: Findings explicitly rejected by validator are discarded
5. **Validator Skip**: If validator runs but skips a finding, it's discarded

Use `--no-merged-only` to see all raw findings from each engine (legacy behavior).

**Example:**
```bash
# High-precision mode (default): merged/confirmed/high-confidence findings
pvs analyze myapp.py

# See all findings including potential false positives
pvs analyze myapp.py --no-merged-only

# Without validator, only high-confidence (≥0.7) findings appear
pvs analyze myapp.py --no-validate
```

## Architecture

```
py-vuln-scout/
├── src/py_vuln_scout/
│   ├── analysis/         # AST utils, taint analysis, fingerprinting
│   ├── cache/            # Disk-based LLM response caching
│   ├── engines/          # Four analysis engines
│   ├── llm/              # Ollama client and prompts
│   ├── output/           # Finding models and formatters
│   ├── rules/            # Rule definitions and schemas
│   │   ├── schema/       # JSON schemas for validation
│   │   └── cwe-79/       # CWE-79 specific rules
│   ├── cli.py            # Typer-based CLI
│   └── config.py         # Configuration management
├── tests/                # Comprehensive test suite
└── examples/             # Example vulnerable code
```

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass and linters are happy
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with [Ollama](https://ollama.ai/) for local LLM inference
- Uses [libcst](https://libcst.readthedocs.io/) for Python AST manipulation
- CLI powered by [Typer](https://typer.tiangolo.com/)
- Schema validation with [jsonschema](https://python-jsonschema.readthedocs.io/)

## Support

- Report issues: [GitHub Issues](https://github.com/ybraz/py-vuln-scout/issues)
- Documentation: This README and inline docstrings
- Examples: See `examples/` directory

---

**Warning**: This tool is for security research and testing purposes only. Always validate findings manually and obtain proper authorization before testing systems you don't own.
