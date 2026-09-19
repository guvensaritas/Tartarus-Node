import os
import json
import sqlite3
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "state_memory", "state_memory.db")
QUARANTINE_LOG = os.path.join(BASE_DIR, "quarantine", "malware_intel.log")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Tartarus-Node | SOC Dashboard</title>
    <style>
        body { background-color: #0d1117; color: #c9d1d9; font-family: monospace; margin: 0; padding: 20px; }
        h1 { color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 10px; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px; }
        .card { background-color: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 15px; }
        .card h2 { color: #3fb950; margin-top: 0; font-size: 1.2em; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #30363d; font-size: 0.9em; }
        th { color: #8b949e; }
        .alert { color: #f85149; font-weight: bold; }
    </style>
</head>
<body>
    <h1>Tartarus-Node | Advanced Threat Intelligence</h1>
    <div class="grid">
        <div class="card">
            <h2>Live Attack Feed</h2>
            <table id="attack-table">
                <thead><tr><th>Time</th><th>IP</th><th>Location</th><th>Payload</th></tr></thead>
                <tbody></tbody>
            </table>
        </div>
        <div class="card">
            <h2>Quarantine Zone (Captured Malware)</h2>
            <table id="quarantine-table">
                <thead><tr><th>Time</th><th>Source URL</th><th>SHA-256 / Hash</th></tr></thead>
                <tbody></tbody>
            </table>
        </div>
    </div>
    <script>
        async function fetchStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                
                const attackTbody = document.querySelector('#attack-table tbody');
                attackTbody.innerHTML = '';
                data.attacks.forEach(atk => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `<td>${atk.timestamp}</td><td>${atk.ip}</td><td>${atk.geo}</td><td class="alert">${atk.cmd}</td>`;
                    attackTbody.appendChild(tr);
                });

                const quarTbody = document.querySelector('#quarantine-table tbody');
                quarTbody.innerHTML = '';
                data.quarantine.forEach(q => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `<td>${q.time}</td><td>${q.url}</td><td style="color:#a5d6ff;">${q.hash}</td>`;
                    quarTbody.appendChild(tr);
                });
            } catch (err) {
                console.error("Dashboard Sync Error");
            }
        }
        setInterval(fetchStats, 3000);
        fetchStats();
    </script>
</body>
</html>
"""

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    daemon_threads = True

class DashboardHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the SOC Dashboard."""
    
    def log_message(self, format, *args):
        """Suppress default HTTP server logging."""
        pass

    def do_GET(self):
        """Handle GET requests for UI and API endpoints."""
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode('utf-8'))
            
        elif self.path == '/api/stats':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            payload = {"attacks": [], "quarantine": []}
            
            if os.path.exists(DB_PATH):
                try:
                    conn = sqlite3.connect(DB_PATH)
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT timestamp, ip_address, geo_location, command "
                        "FROM attack_logs ORDER BY id DESC LIMIT 10"
                    )
                    rows = cursor.fetchall()
                    for r in rows:
                        payload["attacks"].append({
                            "timestamp": r[0].split('.')[0].replace('T', ' '),
                            "ip": r[1],
                            "geo": r[2],
                            "cmd": r[3]
                        })
                    conn.close()
                except sqlite3.Error:
                    pass

            if os.path.exists(QUARANTINE_LOG):
                try:
                    with open(QUARANTINE_LOG, 'r', encoding='utf-8') as f:
                        lines = f.readlines()[-10:]
                        for line in reversed(lines):
                            if " | " in line:
                                parts = line.split(" | ")
                                time_val = parts[0].split("]")[0].strip("[")
                                status_parts = {
                                    k.strip(): v.strip() 
                                    for k, v in (p.split("=") for p in parts[1:] if "=" in p)
                                }
                                
                                url = status_parts.get("URL", "Unknown")
                                hash_val = status_parts.get("SHA256", "-")
                                
                                payload["quarantine"].append({
                                    "time": time_val, 
                                    "url": url, 
                                    "hash": hash_val
                                })
                except Exception:
                    pass

            self.wfile.write(json.dumps(payload).encode('utf-8'))
        else:
            self.send_error(404)

def start_dashboard(port: int = 8080) -> None:
    """Initializes and starts the dashboard server on a daemon thread."""
    server = ThreadedHTTPServer(('0.0.0.0', port), DashboardHandler)
    dash_thread = threading.Thread(target=server.serve_forever, daemon=True)
    dash_thread.start()