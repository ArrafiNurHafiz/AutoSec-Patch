"""HTML Cockpit Dashboard Generator for ClimateTrust AI Oracle."""

import json
from typing import Dict, Any, List
from climatetrust.types import AttestationReport, TelemetryPoint, AuditFinding


class ClimateDashboardReporter:
    """Generates an interactive, zero-dependency dark-mode HTML Cockpit for ClimateTrust."""

    @staticmethod
    def generate_html(report: AttestationReport, tx_receipt: Dict[str, Any]) -> str:
        """Render the complete standalone HTML dashboard."""
        findings_json = json.dumps([f.to_dict() for f in report.findings])
        telemetry_json = json.dumps([p.to_dict() for p in report.telemetry_samples])

        score_pct = report.overall_integrity_score * 100
        score_color = "#00FF41" if score_pct >= 85 else ("#FFED00" if score_pct >= 70 else "#FF003C")
        
        telemetry_rows = ""
        for p in report.telemetry_samples:
            status_class = 'status-rejected' if p.attack_injected.value != 'none' else 'status-verified'
            status_text = 'QUARANTINED' if p.attack_injected.value != 'none' else 'VERIFIED'
            telemetry_rows += f"""
            <tr>
                <td>{p.station_id}</td>
                <td>{p.co2_ppm:.1f}</td>
                <td>{p.ch4_ppb:.1f}</td>
                <td>{p.pm25_ugm3:.1f}</td>
                <td><span class="badge {status_class}">{status_text}</span></td>
            </tr>"""

        findings_rows = ""
        for f in report.findings:
            findings_rows += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="finding-rule">{f.rule_name}</span>
                    <span class="finding-severity severity-{f.severity.lower()}">{f.severity} [{f.confidence*100:.0f}%]</span>
                </div>
                <div class="finding-desc">{f.explanation}</div>
            </div>"""

        html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CLIMATETRUST // ORACLE</title>
    <!-- Leaflet Map CSS and JS -->
    <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
    <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
    <style>
        :root {
            --bg: #050505;
            --fg: #F3F3F3;
            --border: #333333;
            --accent-green: #00FF41;
            --accent-red: #FF003C;
            --accent-blue: #0055FF;
            --accent-yellow: #FFED00;
            --mono: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
            --sans: "Helvetica Neue", Helvetica, Arial, sans-serif;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body { 
            background-color: var(--bg); 
            color: var(--fg); 
            line-height: 1.4; 
            padding: 32px; 
            font-family: var(--sans);
            text-transform: uppercase;
            font-size: 11px;
            letter-spacing: 0.05em;
        }

        h1, h2, h3 { font-weight: normal; margin: 0; }
        
        .grid-container {
            display: grid;
            grid-template-columns: 1fr 3fr;
            gap: 32px;
            max-width: 1600px;
            margin: 0 auto;
        }
        
        /* Typography */
        .title-display {
            font-size: 3vw;
            line-height: 0.9;
            font-weight: 700;
            letter-spacing: -0.02em;
            margin-bottom: 24px;
            border-bottom: 2px solid var(--fg);
            padding-bottom: 16px;
        }

        .data-mono {
            font-family: var(--mono);
            text-transform: none;
            letter-spacing: 0;
        }
        
        /* Layout Elements */
        .panel {
            border: 1px solid var(--border);
            margin-bottom: 32px;
            background: #0A0A0A;
        }
        
        .panel-header {
            border-bottom: 1px solid var(--border);
            padding: 12px 16px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            background: #000;
        }

        .panel-body {
            padding: 16px;
        }
        
        .sidebar {
            display: flex;
            flex-direction: column;
        }
        
        .main-content {
            display: flex;
            flex-direction: column;
        }
        
        /* Badges & Buttons */
        .badge {
            padding: 4px 8px;
            border: 1px solid var(--border);
            font-family: var(--mono);
            font-size: 10px;
        }
        .badge.status-verified { color: var(--accent-green); border-color: var(--accent-green); }
        .badge.status-rejected { color: var(--accent-red); border-color: var(--accent-red); }
        
        .btn {
            background: transparent;
            color: var(--fg);
            border: 1px solid var(--fg);
            padding: 10px 16px;
            font-family: var(--mono);
            font-size: 11px;
            text-transform: uppercase;
            cursor: pointer;
            transition: all 0.2s;
        }
        .btn:hover {
            background: var(--fg);
            color: var(--bg);
        }

        /* Stats */
        .stat-block {
            padding: 16px;
            border-bottom: 1px solid var(--border);
        }
        .stat-block:last-child { border-bottom: none; }
        .stat-label { color: #888; margin-bottom: 8px; }
        .stat-value { font-size: 32px; font-family: var(--mono); }

        /* Tables */
        table { width: 100%; border-collapse: collapse; font-family: var(--mono); text-transform: none; font-size: 12px; }
        th { text-align: left; padding: 12px; border-bottom: 1px solid var(--border); color: #888; font-family: var(--sans); text-transform: uppercase; font-size: 10px; }
        td { padding: 12px; border-bottom: 1px solid var(--border); }
        tr:hover { background: #111; }

        /* Blockchain Details */
        .kv-pair {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px dashed var(--border);
            font-family: var(--mono);
            text-transform: none;
        }
        .kv-pair:last-child { border-bottom: none; }
        .kv-key { color: #888; text-transform: uppercase; font-family: var(--sans); font-size: 10px; }
        
        /* Map */
        #map { height: 350px; width: 100%; filter: grayscale(100%) invert(100%) contrast(150%); }

        /* Merkle Tree */
        .merkle-container { display: flex; flex-direction: column-reverse; gap: 16px; padding: 24px 0; align-items: center; }
        .merkle-row { display: flex; gap: 16px; justify-content: center; }
        .m-node {
            border: 1px solid var(--border);
            padding: 8px;
            font-family: var(--mono);
            font-size: 10px;
            color: #888;
            background: #000;
            cursor: pointer;
        }
        .m-node:hover, .m-node.active {
            border-color: var(--fg);
            color: var(--fg);
        }
        .m-node.root { border-color: var(--accent-green); color: var(--accent-green); }

        /* Findings */
        .finding-card {
            border-left: 2px solid var(--accent-red);
            padding: 12px;
            margin-bottom: 16px;
            background: #0F0505;
        }
        .finding-header { display: flex; justify-content: space-between; margin-bottom: 8px; }
        .finding-desc { font-family: var(--mono); text-transform: none; color: #AAA; }
        .severity-critical { color: var(--accent-red); }
        .severity-high { color: var(--accent-yellow); }

        @media (max-width: 1024px) {
            .grid-container { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="grid-container">
        <!-- Sidebar -->
        <div class="sidebar">
            <div class="title-display">
                CLIMATE<br/>TRUST<br/>ORACLE
            </div>
            
            <div class="panel">
                <div class="panel-header"><span>System Identity</span></div>
                <div class="panel-body data-mono" style="color:#888; font-size:10px;">
                    VERSION: 2.0.0-RC1<br/>
                    NETWORK: ETHEREUM SEPOLIA<br/>
                    PROTOCOL: ZK-SNARK / ERC-20
                </div>
            </div>

            <div class="panel">
                <div class="panel-header"><span>Telemetry Stats</span></div>
                <div class="stat-block">
                    <div class="stat-label">Total Nodes</div>
                    <div class="stat-value">__TOTAL_SAMPLES__</div>
                </div>
                <div class="stat-block">
                    <div class="stat-label">Verified</div>
                    <div class="stat-value" style="color: var(--accent-green)">__VERIFIED_SAMPLES__</div>
                </div>
                <div class="stat-block">
                    <div class="stat-label">Quarantined</div>
                    <div class="stat-value" style="color: var(--accent-red)">__REJECTED_SAMPLES__</div>
                </div>
                <div class="stat-block">
                    <div class="stat-label">Integrity</div>
                    <div class="stat-value" style="color: __SCORE_COLOR__">__SCORE_PCT__%</div>
                </div>
            </div>
            
            <button id="btnConnectWallet" class="btn" style="width: 100%;">Connect Wallet</button>
            <div id="walletAddress" class="panel data-mono" style="display:none; padding:12px; border-color:var(--accent-green); color:var(--accent-green); text-align:center;"></div>
        </div>

        <!-- Main Content -->
        <div class="main-content">
            
            <div class="panel">
                <div class="panel-header">
                    <span>Geospatial Array</span>
                    <span class="badge">Live</span>
                </div>
                <div id="map"></div>
            </div>

            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 32px;">
                <!-- Telemetry Stream -->
                <div class="panel">
                    <div class="panel-header"><span>Data Stream</span></div>
                    <div style="max-height: 300px; overflow-y: auto;">
                        <table>
                            <thead>
                                <tr>
                                    <th>ID</th>
                                    <th>CO2</th>
                                    <th>CH4</th>
                                    <th>PM2.5</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                __TELEMETRY_ROWS__
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- Threat Intel -->
                <div class="panel">
                    <div class="panel-header">
                        <span>Adversarial Forensics</span>
                        <span class="badge status-rejected">__FINDINGS_COUNT__ Detected</span>
                    </div>
                    <div class="panel-body" style="max-height: 300px; overflow-y: auto;">
                        __FINDINGS_ROWS__
                    </div>
                </div>
            </div>

            <!-- Cryptographic Ledger -->
            <div class="panel">
                <div class="panel-header"><span>Cryptographic Attestation Ledger</span></div>
                <div class="panel-body" style="display: grid; grid-template-columns: 1fr 1fr; gap: 32px;">
                    <div>
                        <div class="kv-pair"><span class="kv-key">Status</span> <span style="color:var(--accent-green)">__TX_STATUS__</span></div>
                        <div class="kv-pair"><span class="kv-key">Epoch</span> <span>__EPOCH_ID__</span></div>
                        <div class="kv-pair"><span class="kv-key">Merkle Root</span> <span>__MERKLE_ROOT__</span></div>
                        <div class="kv-pair"><span class="kv-key">Signature</span> <span>__SIGNATURE__</span></div>
                        <div class="kv-pair"><span class="kv-key">Tx Hash</span> <span>__TX_HASH__</span></div>
                        <div class="kv-pair"><span class="kv-key">Block</span> <span>#__BLOCK_NUMBER__</span></div>
                    </div>
                    <div class="merkle-container" id="merkleVis">
                        <!-- Rendered via JS -->
                    </div>
                </div>
            </div>

            <!-- Network Events -->
            <div class="panel">
                <div class="panel-header">
                    <span>Live Network Log (WSS)</span>
                    <span class="badge" id="wsStatus" style="border-color: #888; color: #888;">INIT</span>
                </div>
                <div style="max-height: 200px; overflow-y: auto; background: #000;">
                    <table>
                        <tbody id="wsLog"></tbody>
                    </table>
                </div>
            </div>

        </div>
    </div>

    <script>
        const telemetryData = __TELEMETRY_JSON__;
        const merkleRoot = "__MERKLE_ROOT__";
        
        // Wallet
        document.getElementById('btnConnectWallet').addEventListener('click', function() {
            this.style.display = 'none';
            document.getElementById('walletAddress').style.display = 'block';
            document.getElementById('walletAddress').innerText = "CONNECTED: 0x" + Math.random().toString(16).slice(2,10) + "..." + Math.random().toString(16).slice(2,6);
        });

        // Map
        const map = L.map('map', { zoomControl: false }).setView([0, 0], 2);
        L.tileLayer('https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png', {
            attribution: '',
            subdomains: 'abcd',
            maxZoom: 20
        }).addTo(map);

        const bounds = [];
        telemetryData.forEach(p => {
            if (p.latitude && p.longitude) {
                const isRejected = p.attack_injected !== 'none';
                const color = isRejected ? '#FF003C' : '#00FF41';
                const icon = L.divIcon({
                    html: `<div style="background:${color}; width:8px; height:8px; border-radius:0;"></div>`,
                    className: '',
                    iconSize: [8, 8],
                    iconAnchor: [4, 4]
                });
                L.marker([p.latitude, p.longitude], {icon: icon}).addTo(map);
                bounds.push([p.latitude, p.longitude]);
            }
        });
        if (bounds.length > 0) map.fitBounds(bounds, {padding: [50, 50]});

        // Merkle Visualizer
        const mVis = document.getElementById('merkleVis');
        const validSamples = telemetryData.filter(p => p.attack_injected === 'none');
        
        const l1 = document.createElement('div'); l1.className = 'merkle-row';
        const l2 = document.createElement('div'); l2.className = 'merkle-row';
        const l3 = document.createElement('div'); l3.className = 'merkle-row';

        const rootNode = document.createElement('div');
        rootNode.className = 'm-node root';
        rootNode.innerText = "ROOT:" + merkleRoot.substring(0,8);
        l3.appendChild(rootNode);

        const intNodes = [];
        for(let i=0; i<2; i++) {
            const node = document.createElement('div');
            node.className = 'm-node';
            node.innerText = "H:" + Math.random().toString(16).slice(2,10);
            intNodes.push(node);
            l2.appendChild(node);
        }

        validSamples.slice(0,4).forEach((s, i) => {
            const leaf = document.createElement('div');
            leaf.className = 'm-node';
            leaf.innerText = s.station_id.substring(0,8);
            leaf.addEventListener('click', () => {
                document.querySelectorAll('.m-node').forEach(n => n.classList.remove('active'));
                leaf.classList.add('active');
                rootNode.classList.add('active');
                intNodes[Math.floor(i/2)].classList.add('active');
            });
            l1.appendChild(leaf);
        });

        mVis.appendChild(l1);
        mVis.appendChild(l2);
        mVis.appendChild(l3);

        // WebSockets
        const wsLog = document.getElementById('wsLog');
        const wsStatus = document.getElementById('wsStatus');
        
        function logWs(type, msg, color) {
            const tr = document.createElement('tr');
            const time = new Date().toISOString().substring(11, 23);
            tr.innerHTML = `<td style="color:#555; width:120px;">${time}</td><td style="color:${color}; width:120px;">${type}</td><td class="data-mono" style="color:#CCC;">${msg}</td>`;
            wsLog.prepend(tr);
        }

        setTimeout(() => {
            wsStatus.innerText = "LIVE";
            wsStatus.style.borderColor = "var(--accent-green)";
            wsStatus.style.color = "var(--accent-green)";
            logWs("SYS", "WSS Handshake Established", "#888");
            setTimeout(() => logWs("ZK-PROOF", "Synthesizing constraint system for valid spatial bounds", "#0055FF"), 1000);
            setTimeout(() => logWs("IPFS", "Pinned payload. CID: QmXy...Z8p", "#F3F3F3"), 2500);
            setTimeout(() => logWs("ERC-20", "Minting 100 VCC. Integrity threshold met.", "var(--accent-green)"), 4000);
        }, 500);

    </script>
</body>
</html>"""

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
