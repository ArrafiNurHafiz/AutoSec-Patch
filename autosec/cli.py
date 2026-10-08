import os
import sys
import click
from autosec.parser import parse_sarif_or_json
from autosec.client import NebiusNemotronClient
from autosec.patcher import NemotronPatcher
from autosec.runner import apply_patch, run_tests

@click.group()
def main():
    """AutoSec-Patch: Autonomous CVE Remediation Agent."""
    pass

@main.command()
@click.option("--sarif", "-s", required=True, help="Path to SARIF / SAST JSON report file.")
@click.option("--repo", "-r", default=".", help="Root path of target repository.")
@click.option("--test-cmd", "-t", default="pytest", help="Regression test command.")
@click.option("--model", "-m", default=None, help="NVIDIA Nemotron model identifier on Nebius.")
@click.option("--auto-heal/--no-auto-heal", default=True, help="Enable self-healing retry on test failure.")
def remediate(sarif: str, repo: str, test_cmd: str, model: str, auto_heal: bool):
    """Scan report, generate Nemotron patch, and verify with tests."""
    repo_path = os.path.abspath(repo)
    click.echo(f"[*] Parsing security findings from: {sarif}")
    findings = parse_sarif_or_json(sarif)

    if not findings:
        click.echo("[+] No actionable security findings detected.")
        sys.exit(0)

    click.echo(f"[+] Loaded {len(findings)} finding(s). Initializing Nebius Nemotron Engine...")
    client = NebiusNemotronClient(model=model) if model else NebiusNemotronClient()
    patcher = NemotronPatcher(client)

    for idx, finding in enumerate(findings, 1):
        target_file = os.path.join(repo_path, finding.file_path)
        click.echo(f"\n--- Processing Finding [{idx}/{len(findings)}]: {finding.rule_id} ---")
        click.echo(f"    Target: {finding.file_path}:{finding.start_line}")
        click.echo(f"    Detail: {finding.message}")

        if not os.path.exists(target_file):
            click.echo(f"[!] Target file not found: {target_file}. Skipping.")
            continue

        with open(target_file, "r", encoding="utf-8") as f:
            source_code = f.read()

        click.echo("[*] Requesting patch from NVIDIA Nemotron (Nebius Token Factory)...")
        patch_diff = patcher.generate_patch(finding, source_code)
        click.echo(f"[+] Generated Diff:\n{patch_diff}\n")

        click.echo("[*] Applying patch...")
        success, msg = apply_patch(repo_path, patch_diff)
        if not success:
            click.echo(f"[!] Failed to apply patch: {msg}")
            continue

        click.echo(f"[*] Running regression test suite ({test_cmd})...")
        passed, test_out = run_tests(repo_path, test_cmd)
        if passed:
            click.echo(f"[SUCCESS] Security vulnerability {finding.rule_id} fixed and all regression tests passed!")
        else:
            click.echo(f"[FAIL] Regression tests failed after patch.")
            if auto_heal:
                click.echo("[*] Initiating Self-Healing feedback loop to Nemotron...")
                healed_diff = patcher.heal_patch(finding, source_code, test_out)
                click.echo(f"[+] Healed Diff:\n{healed_diff}\n")
                success_heal, msg_heal = apply_patch(repo_path, healed_diff)
                if success_heal:
                    passed_heal, _ = run_tests(repo_path, test_cmd)
                    if passed_heal:
                        click.echo(f"[SUCCESS] Self-healed patch passed all tests!")
                    else:
                        click.echo("[!] Self-healing attempt still failed regression.")
            else:
                click.echo("[!] Auto-heal disabled. Manual inspection required.")

if __name__ == "__main__":
    main()
