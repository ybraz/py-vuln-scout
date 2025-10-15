"""Simple XSS example for testing."""

from flask import Flask, request, render_template_string

app = Flask(__name__)


@app.route("/vuln")
def vulnerable():
    """Vulnerable: Direct concatenation with user input."""
    name = request.args.get("name", "Guest")
    return render_template_string("<h1>Hello " + name + "</h1>")
