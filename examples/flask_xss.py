"""Example Flask application with XSS vulnerabilities for testing."""

from flask import Flask, request, render_template_string, escape, Markup

app = Flask(__name__)


@app.route("/vulnerable1")
def vulnerable1():
    """Vulnerable: Direct concatenation with user input."""
    name = request.args.get("name", "Guest")
    # CWE-79: XSS via render_template_string with string concatenation
    return render_template_string("<h1>Hello " + name + "</h1>")


@app.route("/vulnerable2")
def vulnerable2():
    """Vulnerable: f-string with user input."""
    title = request.form.get("title", "Welcome")
    # CWE-79: XSS via f-string in render_template_string
    html = f"<div><h2>{title}</h2></div>"
    return render_template_string(html)


@app.route("/vulnerable3")
def vulnerable3():
    """Vulnerable: Using Markup without escaping."""
    content = request.values.get("content", "")
    # CWE-79: XSS via Markup (marks as safe without sanitization)
    return Markup(f"<p>{content}</p>")


@app.route("/safe1")
def safe1():
    """Safe: Using template variables with autoescape."""
    name = request.args.get("name", "Guest")
    # Safe: Template variables are autoescaped by default
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)


@app.route("/safe2")
def safe2():
    """Safe: Explicit escaping."""
    name = request.args.get("name", "Guest")
    # Safe: Explicitly escaped before rendering
    return render_template_string("<h1>Hello " + escape(name) + "</h1>")


@app.route("/safe3")
def safe3():
    """Safe: Using |e filter in template."""
    name = request.args.get("name", "Guest")
    # Safe: |e filter explicitly escapes
    return render_template_string("<h1>Hello {{ name|e }}</h1>", name=name)


@app.route("/vulnerable4")
def vulnerable4():
    """Vulnerable: Complex case with multiple sources."""
    user_id = request.args.get("id", "")
    message = request.headers.get("X-Message", "")
    # CWE-79: XSS with multiple untrusted sources
    template = f"""
    <div>
        <p>User ID: {user_id}</p>
        <p>Message: {message}</p>
    </div>
    """
    return render_template_string(template)


if __name__ == "__main__":
    app.run(debug=True)
