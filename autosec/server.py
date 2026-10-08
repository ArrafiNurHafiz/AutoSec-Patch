from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import os
import threading
from typing import Optional

COCKPIT_DATA = {
    "status": "ONLINE",
    "engine": "AutoSec Multi-Agent Co-Evolution Swarm",
    "model_cluster": "NVIDIA Nemotron (Nano/Super/Ultra) via Nebius Token Factory",
    "findings_processed": 3,
    "immunity_rate": 100.0,
    "consensus_voting": "ACTIVE",
    "formal_verification": "Z3/SMT BOUNDED",
}

class CockpitApiHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(COCKPIT_DATA).encode("utf-8"))
        elif self.path == "/" or self.path == "/dashboard":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            dashboard_file = "cockpit_demo.html"
            if os.path.exists(dashboard_file):
                with open(dashboard_file, "rb") as f:
                    self.wfile.write(f.read())
            else:
                self.wfile.write(b"<h1>AutoSec Cockpit Server Active</h1>")
        else:
            self.send_response(404)
            self.end_headers()

def start_cockpit_server(port: int = 8080) -> HTTPServer:
    server = HTTPServer(("0.0.0.0", port), CockpitApiHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server
