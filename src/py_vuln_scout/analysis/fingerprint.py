"""Generate stable fingerprints for code snippets."""

import hashlib
import re


def normalize_code(code: str) -> str:
    """Normalize code by removing comments and extra whitespace.

    Args:
        code: Raw Python code

    Returns:
        Normalized code string
    """
    # Remove single-line comments
    code = re.sub(r"#.*$", "", code, flags=re.MULTILINE)
    # Remove multi-line strings used as comments (docstrings)
    code = re.sub(r'""".*?"""', "", code, flags=re.DOTALL)
    code = re.sub(r"'''.*?'''", "", code, flags=re.DOTALL)
    # Normalize whitespace
    code = re.sub(r"\s+", " ", code)
    return code.strip()


def generate_fingerprint(file_path: str, line_start: int, line_end: int, code: str) -> str:
    """Generate a stable SHA256 fingerprint for a code snippet.

    Args:
        file_path: Path to the file
        line_start: Starting line number
        line_end: Ending line number
        code: Code snippet

    Returns:
        SHA256 hash as hex string
    """
    normalized = normalize_code(code)
    # Include file path and line numbers for uniqueness
    composite = f"{file_path}:{line_start}-{line_end}:{normalized}"
    return f"sha256:{hashlib.sha256(composite.encode('utf-8')).hexdigest()}"
