import os
import click
from autosec.engine import CoEvolutionEngine
from autosec.reporter import generate_interactive_html_dashboard


@click.group()
def main():
    """AutoSec-Patch: Next-Gen Autonomous SecOps Co-Evolution Swarm."""
    pass


@main.command()
@click.option(
    "--sarif", "-s", required=True, help="Path to SARIF / SAST finding report."
)
@click.option("--repo", "-r", default=".", help="Target codebase repository root.")
@click.option(
    "--test-cmd",
    "-t",
    default="python3 -m unittest examples/test_vulnerable.py",
    help="Regression test command.",
)
@click.option(
    "--max-iterations", "-i", default=3, help="Max Red-Blue co-evolution rounds."
)
@click.option(
    "--report",
    "-o",
    default="dashboard.html",
    help="Path for interactive HTML cockpit report.",
)
def remediate(sarif: str, repo: str, test_cmd: str, max_iterations: int, report: str):
    """Execute autonomous co-evolution remediation swarm."""
    click.echo("=" * 65)
    click.echo("  🛡️  AUTOSEC-PATCH: CO-EVOLUTION SECOPS SWARM  🛡️")
    click.echo("  Powered by Nebius Token Factory & NVIDIA Nemotron")
    click.echo("=" * 65)

    engine = CoEvolutionEngine(repo_path=repo, max_iterations=max_iterations)
    results = engine.process_sarif(sarif, test_cmd=test_cmd)

    click.echo(f"\n[+] Evaluated {len(results)} vulnerability finding(s).")
    for r in results:
        status = (
            "✅ IMMUNE" if (r.verified_secure and r.regression_passed) else "❌ FAILED"
        )
        click.echo(
            f"  • {r.finding.rule_id} ({r.finding.cwe}): {status} [{r.iterations} iteration(s)]"
        )

    # Generate Cockpit
    report_file = generate_interactive_html_dashboard(results, output_path=report)
    click.echo(
        f"\n[+] Interactive SecOps Cockpit Report generated: {os.path.abspath(report_file)}"
    )


if __name__ == "__main__":
    main()
