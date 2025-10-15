# Contributing to py-vuln-scout

Thank you for your interest in contributing to py-vuln-scout! This document provides guidelines and instructions for contributing.

## Development Setup

### Prerequisites

- Python 3.11 or higher
- Git
- Ollama (for LLM-based features)

### Setting Up Your Development Environment

1. **Fork and clone the repository**

```bash
git clone https://github.com/ybraz/py-vuln-scout.git
cd py-vuln-scout
```

2. **Create a virtual environment**

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install development dependencies**

```bash
make install-dev
# or
pip install -e ".[dev]"
```

4. **Install pre-commit hooks**

```bash
make pre-commit
# or
pre-commit install
```

5. **Verify installation**

```bash
pvs version
pvs self-test
```

## Development Workflow

### Running Tests

```bash
# Run all tests
make test

# Run specific test file
pytest tests/test_regex_engine.py

# Run with coverage
pytest --cov=py_vuln_scout --cov-report=html
```

### Code Quality

```bash
# Run linters
make lint

# Format code
make format

# Check types
mypy src/
```

### Pre-commit Hooks

Pre-commit hooks will automatically run on every commit:
- Black (code formatting)
- Ruff (linting)
- MyPy (type checking)
- YAML/JSON validation

## Adding New Features

### Adding a New CWE

1. **Create rule files**

Create both regex and LLM rules:
- `src/py_vuln_scout/rules/cwe-XXX/regex.json`
- `src/py_vuln_scout/rules/cwe-XXX/llm.json`

2. **Validate against schemas**

Ensure your rules conform to:
- `src/py_vuln_scout/rules/schema/regex_rule.schema.json`
- `src/py_vuln_scout/rules/schema/llm_rule.schema.json`

3. **Update taint primitives**

Add sources/sinks/sanitizers in `src/py_vuln_scout/analysis/taint_primitives.py`

4. **Add tests**

Create test file: `tests/test_cwe_XXX.py`

5. **Add example**

Create vulnerable code example: `examples/cwe_XXX_example.py`

### Adding a New Engine

1. **Create engine file**

`src/py_vuln_scout/engines/new_engine.py`

2. **Implement required interface**

```python
class NewEngine:
    def __init__(self, rules: list[dict[str, Any]]) -> None:
        ...

    def analyze(self, file_path: str, code: str) -> list[Finding]:
        ...
```

3. **Integrate into CLI**

Update `src/py_vuln_scout/cli.py` to include the new engine

4. **Add tests**

Create `tests/test_new_engine.py`

## Code Style

### Python Style Guide

- Follow PEP 8
- Use type hints for all functions
- Maximum line length: 100 characters
- Use descriptive variable names
- Add docstrings (Google style) to all public functions

### Example

```python
def analyze_code(file_path: str, code: str, confidence_min: float = 0.35) -> list[Finding]:
    """Analyze Python code for vulnerabilities.

    Args:
        file_path: Path to the file being analyzed
        code: Python source code to analyze
        confidence_min: Minimum confidence threshold

    Returns:
        List of findings above the confidence threshold

    Raises:
        AnalysisError: If analysis fails
    """
    ...
```

## Testing Guidelines

### Test Structure

- Use pytest fixtures in `tests/conftest.py`
- Mock external dependencies (Ollama, file I/O)
- Test both positive and negative cases
- Test error handling

### Example Test

```python
def test_regex_engine_detects_vulnerability(sample_code, sample_regex_rule):
    """Test that regex engine detects vulnerable patterns."""
    engine = RegexEngine([sample_regex_rule])
    findings = engine.analyze("test.py", sample_code)

    assert len(findings) > 0
    assert findings[0].cwe_id == "CWE-79"
    assert findings[0].confidence > 0.5
```

## Documentation

### Updating Documentation

- Update README.md for user-facing changes
- Add inline comments for complex logic
- Update docstrings when changing function signatures
- Add examples for new features

### Documentation Style

- Use clear, concise language
- Include code examples
- Explain the "why" not just the "what"
- Keep examples up to date

## Pull Request Process

1. **Create a feature branch**

```bash
git checkout -b feature/my-new-feature
```

2. **Make your changes**

- Write code
- Add tests
- Update documentation
- Run linters and tests

3. **Commit your changes**

```bash
git add .
git commit -m "Add feature: description of changes"
```

Use conventional commit messages:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Adding tests
- `refactor:` Code refactoring
- `chore:` Maintenance tasks

4. **Push to your fork**

```bash
git push origin feature/my-new-feature
```

5. **Create a Pull Request**

- Provide a clear description
- Reference any related issues
- Ensure CI passes
- Request review

### PR Checklist

- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] Code follows style guidelines
- [ ] All tests pass
- [ ] Pre-commit hooks pass
- [ ] No merge conflicts

## Reporting Issues

### Bug Reports

Include:
- Python version
- Ollama version (if applicable)
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Error messages/stack traces

### Feature Requests

Include:
- Clear description of the feature
- Use case/motivation
- Proposed implementation (optional)
- Examples

## Code Review

### For Reviewers

- Be respectful and constructive
- Explain the reasoning behind suggestions
- Approve if no blocking issues
- Focus on:
  - Correctness
  - Test coverage
  - Documentation
  - Performance implications

### For Contributors

- Respond to feedback promptly
- Ask for clarification if needed
- Don't take criticism personally
- Update PR based on feedback

## Release Process

Maintainers follow semantic versioning:
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes

## Questions?

- Open a GitHub Discussion
- Join our community chat (if applicable)
- Email maintainers

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

## Recognition

Contributors will be recognized in:
- GitHub contributors page
- Release notes
- README acknowledgments

Thank you for contributing to py-vuln-scout!
