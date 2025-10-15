"""Taint analysis primitives for tracking data flow in Python code."""

from typing import Final

# CWE-79 (XSS) specific taint sources
XSS_SOURCES: Final[list[str]] = [
    "request.args.get",
    "request.args",
    "request.form.get",
    "request.form",
    "request.values.get",
    "request.values",
    "request.get_json",
    "request.json",
    "request.headers.get",
    "request.headers",
    "request.cookies.get",
    "request.cookies",
    "request.data",
    "request.query_params",  # Django REST
    "request.POST.get",  # Django
    "request.GET.get",  # Django
    "input",  # Standard input (less common in web apps)
]

# CWE-79 (XSS) specific taint sinks
XSS_SINKS: Final[list[str]] = [
    "render_template_string",  # Flask - dangerous when used with concatenation
    "render_template",  # Flask - safer but can be misused
    "HttpResponse",  # Django - when content_type is HTML
    "Response",  # Flask Response object
    "make_response",  # Flask
    "mark_safe",  # Django - explicitly marks string as safe (dangerous)
    "Markup",  # Flask/Jinja2 - similar to mark_safe
    "JsonResponse",  # Django - less dangerous but can be misused
]

# Sanitization functions that should reduce confidence
XSS_SANITIZERS: Final[list[str]] = [
    "escape",  # Flask/Django escape
    "flask.escape",
    "markupsafe.escape",
    "Markup.escape",
    "html.escape",
    "bleach.clean",
    "bleach.linkify",
    "|e",  # Jinja2 escape filter
    "|escape",  # Jinja2 escape filter (verbose)
    "autoescape",  # Template autoescape context
]

# Framework detection patterns
FRAMEWORK_INDICATORS: Final[dict[str, list[str]]] = {
    "Flask": [
        "from flask import",
        "import flask",
        "@app.route",
        "Flask(__name__)",
        "render_template",
    ],
    "Django": [
        "from django",
        "import django",
        "HttpResponse",
        "render",
        "django.shortcuts",
    ],
    "Jinja2": [
        "from jinja2 import",
        "import jinja2",
        "Template(",
        "Environment(",
    ],
}


def get_sources_for_cwe(cwe_id: str) -> list[str]:
    """Get taint sources for a specific CWE.

    Args:
        cwe_id: CWE identifier (e.g., "CWE-79")

    Returns:
        List of taint source patterns
    """
    if cwe_id == "CWE-79":
        return XSS_SOURCES.copy()
    return []


def get_sinks_for_cwe(cwe_id: str) -> list[str]:
    """Get taint sinks for a specific CWE.

    Args:
        cwe_id: CWE identifier (e.g., "CWE-79")

    Returns:
        List of taint sink patterns
    """
    if cwe_id == "CWE-79":
        return XSS_SINKS.copy()
    return []


def get_sanitizers_for_cwe(cwe_id: str) -> list[str]:
    """Get sanitization functions for a specific CWE.

    Args:
        cwe_id: CWE identifier (e.g., "CWE-79")

    Returns:
        List of sanitizer patterns
    """
    if cwe_id == "CWE-79":
        return XSS_SANITIZERS.copy()
    return []


def detect_framework(code: str) -> list[str]:
    """Detect web frameworks used in the code.

    Args:
        code: Python source code

    Returns:
        List of detected framework names
    """
    detected = []
    for framework, indicators in FRAMEWORK_INDICATORS.items():
        if any(indicator in code for indicator in indicators):
            detected.append(framework)
    return detected
