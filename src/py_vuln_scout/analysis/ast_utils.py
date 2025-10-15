"""AST utilities for Python code analysis."""

import ast
import json
from typing import Any


def parse_code(code: str) -> ast.AST | None:
    """Parse Python code into an AST.

    Args:
        code: Python source code

    Returns:
        AST root node, or None if parsing fails
    """
    try:
        return ast.parse(code)
    except SyntaxError:
        return None


def find_function_calls(tree: ast.AST) -> list[str]:
    """Extract all function call names from an AST.

    Args:
        tree: AST root node

    Returns:
        List of function call names (including method calls like 'obj.method')
    """
    calls = []

    class CallVisitor(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call) -> None:
            # Handle simple function calls
            if isinstance(node.func, ast.Name):
                calls.append(node.func.id)
            # Handle method calls (e.g., request.args.get)
            elif isinstance(node.func, ast.Attribute):
                call_name = _get_full_attribute_name(node.func)
                if call_name:
                    calls.append(call_name)
            self.generic_visit(node)

    CallVisitor().visit(tree)
    return calls


def _get_full_attribute_name(node: ast.Attribute) -> str | None:
    """Recursively build full attribute name (e.g., 'request.args.get').

    Args:
        node: Attribute AST node

    Returns:
        Full dotted name or None
    """
    parts = []
    current = node

    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value

    if isinstance(current, ast.Name):
        parts.append(current.id)
        parts.reverse()
        return ".".join(parts)

    return None


def extract_snippet(code: str, line_start: int, line_end: int, max_lines: int = 12) -> str:
    """Extract a code snippet from source code.

    Args:
        code: Full source code
        line_start: Starting line (1-indexed)
        line_end: Ending line (1-indexed)
        max_lines: Maximum lines to include

    Returns:
        Code snippet
    """
    lines = code.splitlines()
    # Convert to 0-indexed
    start_idx = max(0, line_start - 1)
    end_idx = min(len(lines), line_end)

    # Limit to max_lines
    if end_idx - start_idx > max_lines:
        end_idx = start_idx + max_lines

    return "\n".join(lines[start_idx:end_idx])


def ast_to_json(tree: ast.AST, max_depth: int = 3) -> dict[str, Any]:
    """Convert AST to a simplified JSON representation.

    Args:
        tree: AST root node
        max_depth: Maximum depth to traverse

    Returns:
        Dictionary representation of AST
    """

    def _node_to_dict(node: ast.AST, depth: int = 0) -> dict[str, Any] | str:
        if depth > max_depth:
            return "..."

        if isinstance(node, ast.AST):
            result: dict[str, Any] = {"type": node.__class__.__name__}

            for field, value in ast.iter_fields(node):
                if isinstance(value, list):
                    result[field] = [_node_to_dict(item, depth + 1) for item in value]
                elif isinstance(value, ast.AST):
                    result[field] = _node_to_dict(value, depth + 1)
                else:
                    result[field] = value

            return result
        return str(node)

    return _node_to_dict(tree)


def get_line_range(node: ast.AST) -> tuple[int, int]:
    """Get the line range for an AST node.

    Args:
        node: AST node

    Returns:
        Tuple of (line_start, line_end), 1-indexed
    """
    line_start = getattr(node, "lineno", 1)
    line_end = getattr(node, "end_lineno", line_start)
    return line_start, line_end
