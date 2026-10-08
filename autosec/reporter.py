import os
import json
from typing import List, Dict
from autosec.types import RemediationResult

def generate_interactive_html_dashboard(results: List[RemediationResult], output_path: str = "report.html") -> str:
    """Generates an enterprise-grade dark-themed interactive SecOps report."""
    total_findings = len(results)
    total_secured = sum(1 for r in results if r.verified_secure and r.regression_passed)
    success_rate = (total_secured / total_findings * 100) if total_findings > 0 else 100.0

    cards_html = ""
    for idx, r in enumerate(results, 1):
        status_color = "#10b981" if (r.verified_secure and r.regression_passed) else "#ef4444"
        status_text = "VERIFIED IMMUNE" if (r.verified_secure and r.regression_passed) else "FAILED VERIFICATION"

        timeline_items = ""
        for t in r.timeline:
            timeline_items += f"""
            <div class="timeline-step">
                <div class="step-header">
                    <span class="agent-badge">{t.agent_name}</span>
                    <span class="model-badge">{t.model_used}</span>
                </div>
                <div class="step-tokens">Tokens: {t.token_usage.get('prompt', 0) + t.token_usage.get('completion', 0)}</div>
            </div>
            """

        cards_html += f"""
        <div class="card">
            <div class="card-header">
                <div>
                    <span class="badge cwe-badge">{r.finding.cwe or 'CWE'}</span>
                    <span class="rule-title">{r.finding.rule_id}</span>
                </div>
                <span class="badge status-badge" style="background: {status_color}22; color: {status_color}; border: 1px solid {status_color};">
                    {status_text}
                </span>
            </div>
            <div class="card-body">
                <p class="file-path">📁 <code>{r.finding.file_path}:{r.finding.start_line}</code></p>
                <p class="finding-msg">{r.finding.message}</p>
                
                <div class="grid-2">
                    <div>
                        <h4>⚡ Blast Radius Impacted Nodes</h4>
                        <div class="tag-container">
                            {''.join(f'<span class="tag">{node}</span>' for node in r.blast_radius_nodes)}
                        </div>
                    </div>
                    <div>
                        <h4>🔄 Co-Evolution Loop</h4>
                        <p>Iterations: <strong>{r.iterations}</strong> | Self-Healing: <strong>Active</strong></p>
                    </div>
                </div>

                <h4>🛡️ Synthesized Invariant-Preserving Diff</h4>
                <pre class="code-block"><code>{r.final_patch}</code></pre>

                <h4>🤖 Swarm Orchestration Timeline</h4>
                <div class="timeline-container">
                    {timeline_items}
                </div>
            </div>
        </div>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>AutoSec-Patch: Autonomous Co-Evolution SecOps Cockpit</title>
    <style>
        :root {{
            --bg: #090d16;
            --surface: #111827;
            --border: #1f2937;
            --primary: #3b82f6;
            --accent: #8b5cf6;
            --text: #f9fafb;
            --text-muted: #9ca3af;
        }}
        body {{
            margin: 0;
            padding: 2rem;
            background: var(--bg);
            color: var(--text);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border);
            padding-bottom: 1.5rem;
            margin-bottom: 2rem;
        }}
        .title h1 {{ margin: 0; font-size: 1.8rem; background: linear-gradient(135deg, #60a5fa, #a78bfa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .title p {{ margin: 0.3rem 0 0; color: var(--text-muted); font-size: 0.9rem; }}
        .metrics {{ display: flex; gap: 1.5rem; }}
        .metric-box {{
            background: var(--surface);
            padding: 1rem 1.5rem;
            border-radius: 8px;
            border: 1px solid var(--border);
            text-align: center;
        }}
        .metric-val {{ font-size: 1.5rem; font-weight: bold; color: var(--primary); }}
        .metric-label {{ font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase; }}
        .card {{
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 10px;
            margin-bottom: 1.5rem;
            overflow: hidden;
        }}
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 1.2rem;
            background: #161f30;
            border-bottom: 1px solid var(--border);
        }}
        .card-body {{ padding: 1.2rem; }}
        .badge {{ padding: 0.3rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }}
        .cwe-badge {{ background: #374151; color: #fbbf24; margin-right: 0.5rem; }}
        .rule-title {{ font-weight: 600; font-size: 1.05rem; }}
        .file-path {{ color: var(--text-muted); font-size: 0.9rem; }}
        .finding-msg {{ font-size: 0.95rem; line-height: 1.5; }}
        .grid-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin: 1rem 0; }}
        .tag-container {{ display: flex; flex-wrap: wrap; gap: 0.5rem; }}
        .tag {{ background: #1f2937; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.8rem; color: #60a5fa; }}
        .code-block {{
            background: #030712;
            padding: 1rem;
            border-radius: 6px;
            overflow-x: auto;
            border: 1px solid var(--border);
            font-family: monospace;
            font-size: 0.85rem;
            color: #34d399;
        }}
        .timeline-container {{ display: flex; gap: 1rem; margin-top: 0.5rem; overflow-x: auto; padding-bottom: 0.5rem; }}
        .timeline-step {{
            background: #0b1120;
            border: 1px solid var(--border);
            padding: 0.7rem;
            border-radius: 6px;
            min-width: 220px;
        }}
        .agent-badge {{ font-weight: 600; font-size: 0.8rem; color: #f472b6; }}
        .model-badge {{ font-size: 0.7rem; color: var(--text-muted); display: block; }}
        .step-tokens {{ font-size: 0.75rem; color: var(--text-muted); margin-top: 0.4rem; }}
    </style>
</head>
<body>
    <div class="header">
        <div class="title">
            <h1>AutoSec-Patch Co-Evolution Cockpit</h1>
            <p>Adversarial Red/Blue Multi-Agent Remediation via Nebius Token Factory & NVIDIA Nemotron</p>
        </div>
        <div class="metrics">
            <div class="metric-box">
                <div class="metric-val">{total_findings}</div>
                <div class="metric-label">Findings</div>
            </div>
            <div class="metric-box">
                <div class="metric-val">{success_rate:.0f}%</div>
                <div class="metric-label">Immunity Rate</div>
            </div>
            <div class="metric-box">
                <div class="metric-val">Nebius Cloud</div>
                <div class="metric-label">Inference Engine</div>
            </div>
        </div>
    </div>
    
    <div class="findings-list">
        {cards_html}
    </div>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path
