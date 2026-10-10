import os
from typing import List
from autosec.types import RemediationResult


def generate_interactive_html_dashboard(
    results: List[RemediationResult], output_path: str = "report.html"
) -> str:
    """Generates an enterprise-grade dark-themed interactive SecOps report."""
    total_findings = len(results)
    total_secured = sum(1 for r in results if r.verified_secure and r.regression_passed)
    success_rate = (
        (total_secured / total_findings * 100) if total_findings > 0 else 100.0
    )

    cards_html = ""
    for idx, r in enumerate(results, 1):
        is_secure = r.verified_secure and r.regression_passed
        status_color_bg = "bg-green-500/10" if is_secure else "bg-red-500/10"
        status_color_text = "text-green-500" if is_secure else "text-red-500"
        status_color_border = (
            "border-green-500/30" if is_secure else "border-red-500/30"
        )
        status_text = "VERIFIED IMMUNE" if is_secure else "FAILED VERIFICATION"

        timeline_items = ""
        for t in r.timeline:
            timeline_items += f"""
            <div class="bg-gray-900 border border-gray-800 p-3 rounded-lg min-w-[220px]">
                <div class="flex justify-between items-center mb-1">
                    <span class="font-semibold text-xs text-pink-400">{t.agent_name}</span>
                </div>
                <span class="text-[11px] text-gray-400 block mb-2">{t.model_used}</span>
                <div class="text-[11px] text-gray-500">Tokens: {t.token_usage.get('prompt', 0) + t.token_usage.get('completion', 0)}</div>
            </div>
            """

        cards_html += f"""
        <div class="bg-surface border border-border rounded-xl overflow-hidden shadow-lg">
            <div class="flex justify-between items-center p-5 bg-gray-900/50 border-b border-border">
                <div class="flex items-center gap-3">
                    <span class="px-2 py-1 rounded bg-gray-700 text-yellow-400 text-xs font-semibold">{r.finding.cwe or 'CWE'}</span>
                    <span class="font-semibold text-lg">{r.finding.rule_id}</span>
                </div>
                <span class="px-3 py-1 rounded text-xs font-bold border {status_color_bg} {status_color_text} {status_color_border}">
                    {status_text}
                </span>
            </div>
            <div class="p-6">
                <p class="text-sm text-gray-400 mb-4 flex items-center gap-2">
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v10a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-6l-2-2H5a2 2 0 00-2 2z"></path></svg>
                    <code class="font-mono">{r.finding.file_path}:{r.finding.start_line}</code>
                </p>
                <p class="text-base text-gray-200 mb-6 leading-relaxed">{r.finding.message}</p>
                
                <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                    <div class="bg-gray-900/50 p-4 rounded-lg border border-gray-800">
                        <h4 class="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">⚡ Blast Radius Impacted Nodes</h4>
                        <div class="flex flex-wrap gap-2">
                            {''.join(f'<span class="bg-gray-800 text-blue-400 px-2 py-1 rounded text-xs">{node}</span>' for node in r.blast_radius_nodes)}
                        </div>
                    </div>
                    <div class="bg-gray-900/50 p-4 rounded-lg border border-gray-800">
                        <h4 class="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">🔄 Co-Evolution Loop</h4>
                        <p class="text-sm text-gray-400">Iterations: <strong class="text-gray-200">{r.iterations}</strong> | Self-Healing: <strong class="text-green-400">Active</strong></p>
                    </div>
                </div>

                <div class="mb-6">
                    <h4 class="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">🛡️ Synthesized Invariant-Preserving Diff</h4>
                    <pre class="bg-gray-950 p-4 rounded-lg border border-gray-800 overflow-x-auto text-sm text-emerald-400 font-mono"><code>{r.final_patch}</code></pre>
                </div>

                <div>
                    <h4 class="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">🤖 Swarm Orchestration Timeline</h4>
                    <div class="flex gap-4 overflow-x-auto pb-2">
                        {timeline_items}
                    </div>
                </div>
            </div>
        </div>
        """

    # Read from template
    template_path = os.path.join(
        os.path.dirname(os.path.dirname(__file__)), "templates", "autosec_cockpit.html"
    )
    with open(template_path, "r", encoding="utf-8") as f:
        html_template = f.read()

    html_content = html_template.replace("__TOTAL_FINDINGS__", str(total_findings))
    html_content = html_content.replace("__SUCCESS_RATE__", f"{success_rate:.0f}")
    html_content = html_content.replace("__CARDS_HTML__", cards_html)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    return output_path
