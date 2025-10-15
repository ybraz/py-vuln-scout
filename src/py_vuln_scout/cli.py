"""Command-line interface for py-vuln-scout."""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from py_vuln_scout import __version__
from py_vuln_scout.config import Config, ConfigError, load_config, load_rules_for_cwe
from py_vuln_scout.engines.explainer_engine import ExplainerEngine
from py_vuln_scout.engines.llm_engine import LLMEngine
from py_vuln_scout.engines.regex_engine import RegexEngine
from py_vuln_scout.engines.validator_engine import ValidatorEngine
from py_vuln_scout.llm.ollama_client import OllamaClient
from py_vuln_scout.output.findings import Engine, Finding, FindingFormatter

app = typer.Typer(
    name="pvs",
    help="py-vuln-scout: A modular SAST tool for Python",
    add_completion=False,
)
console = Console()


@app.command()
def analyze(
    file_path: str = typer.Argument(..., help="Python file to analyze"),
    format: str = typer.Option("jsonl", "--format", help="Output format (json or jsonl)"),
    rules_dir: Optional[str] = typer.Option(None, "--rules-dir", help="Rules directory"),
    model: Optional[str] = typer.Option(None, "--model", help="Ollama model name"),
    only: Optional[str] = typer.Option(
        None, "--only", help="Run only specific engine (regex, llm, or both)"
    ),
    no_validate: bool = typer.Option(False, "--no-validate", help="Skip validator engine"),
    no_explain: bool = typer.Option(False, "--no-explain", help="Skip explainer engine"),
    config_path: Optional[str] = typer.Option(
        None, "--config", help="Path to config file"
    ),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Output file path"),
) -> None:
    """Analyze a Python file for vulnerabilities."""
    try:
        # Load configuration
        config = load_config(config_path)
        if rules_dir:
            config.rules_dir = rules_dir
        if model:
            config.model.name = model

        # Validate file exists
        target_file = Path(file_path)
        if not target_file.exists():
            console.print(f"[red]Error: File not found: {file_path}[/red]")
            raise typer.Exit(1)

        # Read code
        code = target_file.read_text(encoding="utf-8")

        # Determine which engines to run
        run_regex = only in [None, "regex", "both"]
        run_llm = only in [None, "llm", "both"]

        # Initialize Ollama client if needed
        ollama_client = None
        if run_llm or not no_validate or not no_explain:
            ollama_client = OllamaClient(
                base_url=config.model.base_url,
                model=config.model.name,
                timeout=config.model.timeout,
                cache_enabled=config.model.cache_enabled,
            )

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            # Run regex engine
            regex_findings = []
            if run_regex:
                task = progress.add_task("Running regex engine...", total=None)
                regex_rules = load_rules_for_cwe("CWE-79", config.rules_dir, "regex")
                if regex_rules:
                    regex_engine = RegexEngine(regex_rules)
                    regex_findings = regex_engine.analyze(file_path, code)
                progress.remove_task(task)

            # Run LLM engine
            llm_findings = []
            if run_llm and ollama_client:
                task = progress.add_task("Running LLM engine...", total=None)
                llm_rules = load_rules_for_cwe("CWE-79", config.rules_dir, "llm")
                if llm_rules:
                    llm_engine = LLMEngine(llm_rules, ollama_client)
                    llm_findings = llm_engine.analyze(file_path, code)
                progress.remove_task(task)

            # Merge findings
            all_findings = _merge_findings(regex_findings, llm_findings)

            # Run validator if needed
            if not no_validate and ollama_client:
                validator = ValidatorEngine(ollama_client)
                if validator.should_validate(regex_findings, llm_findings):
                    task = progress.add_task("Running validator engine...", total=None)
                    for finding in all_findings:
                        regex_desc = f"{len(regex_findings)} findings" if regex_findings else "no findings"
                        llm_desc = f"{len(llm_findings)} findings" if llm_findings else "no findings"
                        validator.validate(finding, code, regex_desc, llm_desc)
                    progress.remove_task(task)

            # Run explainer if needed
            if not no_explain and ollama_client:
                task = progress.add_task("Running explainer engine...", total=None)
                explainer = ExplainerEngine(ollama_client)
                for finding in all_findings:
                    explainer.explain(finding, code)
                progress.remove_task(task)

        # Filter by confidence threshold
        filtered_findings = [
            f for f in all_findings if f.confidence >= config.thresholds.confidence_min
        ]

        # Output results
        if output:
            FindingFormatter.write_to_file(filtered_findings, output, format)
            console.print(f"[green]Results written to {output}[/green]")
        else:
            if format == "json":
                console.print(FindingFormatter.to_json(filtered_findings))
            else:
                console.print(FindingFormatter.to_jsonl(filtered_findings))

        # Summary
        console.print(
            f"\n[bold]Summary:[/bold] Found {len(filtered_findings)} "
            f"vulnerability(ies) (confidence >= {config.thresholds.confidence_min})"
        )

    except ConfigError as e:
        console.print(f"[red]Configuration error: {e}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def version() -> None:
    """Show version information."""
    console.print(f"py-vuln-scout version {__version__}")


@app.command()
def self_test() -> None:
    """Run internal self-tests."""
    console.print("[yellow]Running self-tests...[/yellow]")

    try:
        # Test 1: Config loading
        console.print("  Testing config loading... ", end="")
        config = load_config(None)
        console.print("[green]OK[/green]")

        # Test 2: Ollama client
        console.print("  Testing Ollama connection... ", end="")
        client = OllamaClient(
            base_url=config.model.base_url,
            model=config.model.name,
            timeout=5,
        )
        # Simple test prompt
        try:
            response = client.generate("Hello", temperature=0.0, max_tokens=10)
            console.print("[green]OK[/green]")
        except Exception:
            console.print("[yellow]SKIP (Ollama not available)[/yellow]")

        # Test 3: Rule loading
        console.print("  Testing rule loading... ", end="")
        rules = load_rules_for_cwe("CWE-79", config.rules_dir, "regex")
        if rules:
            console.print("[green]OK[/green]")
        else:
            console.print("[yellow]WARNING (No rules found)[/yellow]")

        console.print("\n[green]Self-tests completed![/green]")

    except Exception as e:
        console.print(f"\n[red]Self-test failed: {e}[/red]")
        raise typer.Exit(1)


def _merge_findings(regex_findings: list[Finding], llm_findings: list[Finding]) -> list[Finding]:
    """Merge findings from regex and LLM engines.

    Args:
        regex_findings: Findings from regex engine
        llm_findings: Findings from LLM engine

    Returns:
        Merged list of findings
    """
    if not regex_findings:
        return llm_findings
    if not llm_findings:
        return regex_findings

    # Simple merge: combine both lists
    # In a more sophisticated version, we'd deduplicate by fingerprint
    all_findings = []

    # Group by fingerprint
    fingerprint_map: dict[str, list[Finding]] = {}
    for finding in regex_findings + llm_findings:
        fp = finding.metadata.fingerprint or ""
        if fp not in fingerprint_map:
            fingerprint_map[fp] = []
        fingerprint_map[fp].append(finding)

    # Merge findings with same fingerprint
    for fp, findings in fingerprint_map.items():
        if len(findings) == 1:
            all_findings.append(findings[0])
        else:
            # Multiple findings with same fingerprint - merge them
            merged = _merge_duplicate_findings(findings)
            all_findings.append(merged)

    return all_findings


def _merge_duplicate_findings(findings: list[Finding]) -> Finding:
    """Merge multiple findings for the same location.

    Args:
        findings: List of findings to merge

    Returns:
        Merged finding
    """
    # Use the finding with highest confidence as base
    base = max(findings, key=lambda f: f.confidence)

    # Combine evidence
    all_evidence = []
    for finding in findings:
        all_evidence.extend(finding.evidence)

    # Remove duplicate evidence
    unique_evidence = []
    seen = set()
    for ev in all_evidence:
        key = (ev.line_start, ev.line_end, ev.snippet)
        if key not in seen:
            seen.add(key)
            unique_evidence.append(ev)

    base.evidence = unique_evidence
    base.engine = Engine.MERGED
    base.confidence = min(1.0, base.confidence + 0.05)  # Small bonus for agreement

    return base


if __name__ == "__main__":
    app()
