"""CLI interface for ClimateTrust AI Oracle."""

import argparse
import time
import sys
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from climatetrust.telemetry import ClimateTelemetryGenerator
from climatetrust.engine import ClimateTrustEngine
from climatetrust.crypto import MerkleTree, OracleSigner, hash_telemetry_point
from climatetrust.blockchain import BlockchainConnector
from climatetrust.reporter import ClimateDashboardReporter
from climatetrust.types import AttestationReport, VerificationStatus

console = Console()


def run_pipeline(samples_per_cluster: int = 5, output_file: str = "cockpit_climate.html", seed: int = 42):
    console.print(Panel.fit(
        "[bold cyan]🌍 ClimateTrust AI Oracle[/bold cyan]\n"
        "[dim]Adversarial AI Verification & Cryptographic Attestation Platform[/dim]\n"
        "[yellow]ClimateChain Global Hackathon 2026 (IEEE Blockchain - Track 4)[/yellow]",
        border_style="cyan"
    ))

    # Step 1: Telemetry Ingestion
    console.print("\n[bold green]Step 1: Ingesting Climate Telemetry & Adversarial Attacks...[/bold green]")
    generator = ClimateTelemetryGenerator(seed=seed)
    epoch_ts = int(time.time())
    points = generator.generate_epoch_telemetry(epoch_timestamp=epoch_ts, samples_per_cluster=samples_per_cluster, inject_attacks=True)
    console.print(f"  Processed [bold]{len(points)}[/bold] observation nodes across 3 spatial clusters.")

    # Step 2: AI Verification Mesh
    console.print("\n[bold green]Step 2: Executing AI Adversarial Verification Mesh...[/bold green]")
    engine = ClimateTrustEngine()
    verified_points, rejected_points, findings, score = engine.audit_epoch(points)

    status = VerificationStatus.VERIFIED if score >= 0.80 else VerificationStatus.REJECTED_TAMPERED
    console.print(f"  Verified Clean Points: [bold green]{len(verified_points)}[/bold green]")
    console.print(f"  Adversarial Tampered Points Quarantined: [bold red]{len(rejected_points)}[/bold red]")
    console.print(f"  Integrity Score: [bold yellow]{score * 100:.2f}%[/bold yellow] (Consensus Threshold: >= 80.00%)")
    console.print(f"  Total Forensics Findings: [bold magenta]{len(findings)}[/bold magenta]")

    # Print Findings Table
    if findings:
        table = Table(title="🛡️ AI Adversarial Findings Summary", border_style="red")
        table.add_column("Rule", style="cyan")
        table.add_column("Station ID", style="white")
        table.add_column("Severity", style="bold red")
        table.add_column("Confidence", style="yellow")
        table.add_column("Explanation", style="dim")

        for f in findings:
            table.add_row(f.rule_name, f.station_id, f.severity, f"{f.confidence*100:.0f}%", f.explanation[:70] + "...")
        console.print(table)

    # Step 3: Merkle Tree & Cryptographic Attestation
    console.print("\n[bold green]Step 3: Constructing Merkle Tree & Cryptographic Attestation...[/bold green]")
    leaves = [hash_telemetry_point(p) for p in verified_points]
    merkle_tree = MerkleTree(leaves)
    signer = OracleSigner()
    epoch_id = f"EPOCH-{epoch_ts}"
    signature = signer.sign_attestation(epoch_id, merkle_tree.root, score, epoch_ts)

    console.print(f"  Epoch ID: [bold]{epoch_id}[/bold]")
    console.print(f"  Merkle Root: [bold cyan]{merkle_tree.root}[/bold cyan]")
    console.print(f"  Oracle ECDSA Signature: [bold dim]{signature[:40]}...[/bold dim]")

    # Step 3b: Zero-Knowledge Proofs & IPFS Serialization
    console.print("\n[bold green]Step 3b: Synthesizing ZK-Proofs & Packaging to IPFS...[/bold green]")
    from climatetrust.zk import ZKClimateProver
    from climatetrust.ipfs import IPFSSerializer

    zk_proofs = [ZKClimateProver.generate_zk_proof(p) for p in verified_points]
    verified_zk_count = sum(1 for zk in zk_proofs if ZKClimateProver.verify_zk_proof(zk))
    console.print(f"  Generated [bold]{len(zk_proofs)}[/bold] NIZK Location & Compliance proofs ([bold green]{verified_zk_count} Verified[/bold green]).")

    ipfs_serializer = IPFSSerializer()
    ipfs_res = ipfs_serializer.package_epoch(
        epoch_id=epoch_id,
        merkle_root=merkle_tree.root,
        integrity_score=score,
        timestamp=epoch_ts,
        verified_points=[p.to_dict() for p in verified_points],
        zk_proofs=zk_proofs,
        audit_findings=[f.to_dict() for f in findings],
    )
    console.print(f"  IPFS CID (v0): [bold magenta]{ipfs_res['cid']}[/bold magenta]")
    console.print(f"  Artifact Path: [dim]{ipfs_res['file_path']}[/dim] ({ipfs_res['size_bytes']} bytes)")

    report = AttestationReport(
        epoch_id=epoch_id,
        timestamp=epoch_ts,
        total_samples=len(points),
        verified_samples=len(verified_points),
        rejected_samples=len(rejected_points),
        overall_integrity_score=score,
        status=status,
        merkle_root=merkle_tree.root,
        oracle_signature=signature,
        findings=findings,
        telemetry_samples=points,
        zk_proofs=zk_proofs,
        ipfs_cid=ipfs_res['cid'],
        ipfs_uri=ipfs_res['uri']
    )

    # Step 4: Smart Contract Submission
    console.print("\n[bold green]Step 4: Committing On-Chain Attestation to Smart Contract...[/bold green]")
    connector = BlockchainConnector()
    receipt = connector.submit_attestation(report)
    console.print(f"  Status: [bold green]{receipt['status']}[/bold green]")
    console.print(f"  Tx Hash: [bold yellow]{receipt['tx_hash']}[/bold yellow]")
    console.print(f"  Block Number: [bold]#{receipt['block_number']}[/bold]")
    console.print(f"  Gas Used: [bold cyan]{receipt['gas_used']}[/bold cyan] units")

    # Step 5: Dashboard Generation
    console.print(f"\n[bold green]Step 5: Generating Cockpit Dashboard to {output_file}...[/bold green]")
    html = ClimateDashboardReporter.generate_html(report, receipt)
    Path(output_file).write_text(html, encoding="utf-8")
    console.print(f"  [bold green]✔ Cockpit Dashboard successfully created at {output_file}[/bold green]")

    return report, receipt


def main():
    parser = argparse.ArgumentParser(description="ClimateTrust AI Oracle CLI")
    subparsers = parser.add_subparsers(dest="command")

    run_parser = subparsers.add_parser("run", help="Run the full ClimateTrust pipeline")
    run_parser.add_argument("--samples", type=int, default=5, help="Samples per cluster")
    run_parser.add_argument("--output", type=str, default="cockpit_climate.html", help="Output HTML file")
    run_parser.add_argument("--seed", type=int, default=42, help="Random seed")

    args = parser.parse_args()
    if args.command == "run" or len(sys.argv) == 1:
        samples = getattr(args, "samples", 5)
        output = getattr(args, "output", "cockpit_climate.html")
        seed = getattr(args, "seed", 42)
        run_pipeline(samples_per_cluster=samples, output_file=output, seed=seed)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
