import json
import os
from typing import Dict, Any
from climatetrust.types import AttestationReport


class ClimateDashboardReporter:
    """Generates an interactive, zero-dependency dark-mode HTML Cockpit for ClimateTrust."""

    @staticmethod
    def generate_html(report: AttestationReport, tx_receipt: Dict[str, Any]) -> str:
        """Render the complete standalone HTML dashboard."""
        findings_json = json.dumps([f.to_dict() for f in report.findings])
        telemetry_json = json.dumps([p.to_dict() for p in report.telemetry_samples])

        score_pct = report.overall_integrity_score * 100
        score_color = (
            "#00FF41"
            if score_pct >= 85
            else ("#FFED00" if score_pct >= 70 else "#FF003C")
        )

        telemetry_rows = ""
        for p in report.telemetry_samples:
            is_rejected = p.attack_injected.value != "none"
            status_class = (
                "border-accent-red text-accent-red"
                if is_rejected
                else "border-accent-green text-accent-green"
            )
            status_text = "QUARANTINED" if is_rejected else "VERIFIED"
            telemetry_rows += f"""
            <tr class="hover:bg-[#111]">
                <td class="p-3 border-b border-border">{p.station_id}</td>
                <td class="p-3 border-b border-border">{p.co2_ppm:.1f}</td>
                <td class="p-3 border-b border-border">{p.ch4_ppb:.1f}</td>
                <td class="p-3 border-b border-border">{p.pm25_ugm3:.1f}</td>
                <td class="p-3 border-b border-border"><span class="border px-2 py-1 font-mono text-[10px] {status_class}">{status_text}</span></td>
            </tr>"""

        findings_rows = ""
        for f in report.findings:
            severity_color = (
                "text-accent-red"
                if f.severity.lower() == "critical"
                else "text-accent-yellow"
            )
            findings_rows += f"""
            <div class="border-l-2 border-accent-red bg-[#0F0505] p-3 mb-4">
                <div class="flex justify-between mb-2">
                    <span>{f.rule_name}</span>
                    <span class="{severity_color}">{f.severity} [{f.confidence*100:.0f}%]</span>
                </div>
                <div class="font-mono normal-case text-[#AAA]">{f.explanation}</div>
            </div>"""

        # Read from template
        template_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "templates",
            "climatetrust_oracle.html",
        )
        with open(template_path, "r", encoding="utf-8") as f:
            html = f.read()

        html = html.replace("__TOTAL_SAMPLES__", str(report.total_samples))
        html = html.replace("__VERIFIED_SAMPLES__", str(report.verified_samples))
        html = html.replace("__REJECTED_SAMPLES__", str(report.rejected_samples))
        html = html.replace("__SCORE_COLOR__", score_color)
        html = html.replace("__SCORE_PCT__", f"{score_pct:.1f}")
        html = html.replace("__TELEMETRY_ROWS__", telemetry_rows)
        html = html.replace("__FINDINGS_COUNT__", str(len(report.findings)))
        html = html.replace("__FINDINGS_ROWS__", findings_rows)
        html = html.replace("__TX_STATUS__", tx_receipt.get("status", "CONFIRMED"))
        html = html.replace("__EPOCH_ID__", report.epoch_id)
        html = html.replace("__MERKLE_ROOT__", report.merkle_root)
        html = html.replace("__SIGNATURE__", report.oracle_signature[:30])
        html = html.replace("__TX_HASH__", tx_receipt.get("tx_hash", "0x...")[0:30])
        html = html.replace("__BLOCK_NUMBER__", str(tx_receipt.get("block_number")))
        html = html.replace("__GAS_USED__", str(tx_receipt.get("gas_used")))
        html = html.replace("__TELEMETRY_JSON__", telemetry_json)

        return html
