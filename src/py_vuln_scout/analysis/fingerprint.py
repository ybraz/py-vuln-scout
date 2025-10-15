"""Generate stable fingerprints for code snippets."""

import hashlib
import re
from typing import Optional

from py_vuln_scout.analysis import ast_utils


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


def generate_fingerprint(
    file_path: str,
    line_start: int,
    line_end: int,
    code: str,
    full_code: Optional[str] = None
) -> str:
    """Generate a stable SHA256 fingerprint for a code snippet.

    Fingerprints are now function-based: findings in the same function
    will have the same fingerprint, enabling better merge logic.

    Args:
        file_path: Path to the file
        line_start: Starting line number
        line_end: Ending line number
        code: Code snippet (for the vulnerable line)
        full_code: Full file code (optional, for function detection)

    Returns:
        SHA256 hash as hex string
    """
    # Try to find the enclosing function
    function_name = None
    if full_code:
        tree = ast_utils.parse_code(full_code)
        if tree:
            function_name = ast_utils.find_enclosing_function(tree, line_start)

    # Build composite key:
    # - If function found: file:function_name (same for all findings in that function)
    # - If not: fallback to file:line_start-line_end (legacy behavior)
    if function_name:
        composite = f"{file_path}:function:{function_name}"
    else:
        normalized = normalize_code(code)
        composite = f"{file_path}:{line_start}-{line_end}:{normalized}"

    return f"sha256:{hashlib.sha256(composite.encode('utf-8')).hexdigest()}"
