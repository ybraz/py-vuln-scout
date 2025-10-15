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
from py_vuln_scout.engines.merger import merge_findings
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
    merged_only: bool = typer.Option(
        True, "--merged-only/--no-merged-only", help="Only show merged/confirmed findings (default: true)"
    ),
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

            # Collect all findings before validation for validator context
            all_findings_pre_validation = regex_findings + llm_findings

            # Run validator if needed
            validated_findings = []
            if not no_validate and ollama_client and all_findings_pre_validation:
                validator = ValidatorEngine(ollama_client)
                if validator.should_validate(regex_findings, llm_findings):
                    task = progress.add_task("Running validator engine...", total=None)
                    for finding in all_findings_pre_validation:
                        regex_desc = f"{len(regex_findings)} findings" if regex_findings else "no findings"
                        llm_desc = f"{len(llm_findings)} findings" if llm_findings else "no findings"
                        validator.validate(finding, code, regex_desc, llm_desc)
                    validated_findings = all_findings_pre_validation
                    progress.remove_task(task)

            # Merge findings with new logic
            all_findings = merge_findings(
                regex_findings,
                llm_findings,
                validated_findings if validated_findings else None,
                merged_only=merged_only,
            )

            # Run explainer if needed
            if not no_explain and ollama_client and all_findings:
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




if __name__ == "__main__":
    app()
