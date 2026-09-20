import os
import json
import sqlite3
import threading
import base64
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Tartarus_Dashboard")

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "state_memory", "state_memory.db")
QUARANTINE_LOG = os.path.join(BASE_DIR, "quarantine", "malware_intel.log")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

def get_auth_credentials():
    """Fetch dynamic username/password from config.json (Strict Production Security)"""
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError(f"Critical Security Error: Config file not found at {CONFIG_PATH}. Copy config.json.example to config.json.")
    
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            config = json.load(f)
            dashboard_cfg = config.get("dashboard", {})
            username = dashboard_cfg.get("username")
            password = dashboard_cfg.get("password")
            
            if not username or not password:
                raise ValueError("Dashboard username or password missing in config.json!")
    except Exception as e:
        logger.error(f"Authentication configuration error: {e}")
        raise

    credentials = f"{username}:{password}"
    encoded = base64.b64encode(credentials.encode('utf-8')).decode('utf-8')
    return f"Basic {encoded}"

EXPECTED_AUTH = get_auth_credentials()

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
        .alert { color: #f85149; font-weight: bold; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { border-bottom: 1px solid #30363d; padding: 8px; text-align: left; }
        th { color: #8b949e; }
    </style>
</head>
<body>
    <h1>Tartarus-Node | Advanced Threat Intelligence</h1>
    <div class="grid">
        <div class="card">
            <h2>Live Attack Feed</h2>
            <table id="attack-table"><thead><tr><th>Time</th><th>IP</th><th>Location</th><th>Payload</th></tr></thead><tbody></tbody></table>
        </div>
        <div class="card">
            <h2>Quarantine Zone</h2>
            <table id="quarantine-table"><thead><tr><th>Time</th><th>Source URL</th><th>Hash</th></tr></thead><tbody></tbody></table>
        </div>
    </div>
    <script>
        async function fetchStats() {
            try {
                const res = await fetch('/api/stats');
                if (res.status === 401) { window.location.reload(); return; }
                const data = await res.json();
                const atkBody = document.querySelector('#attack-table tbody');
                atkBody.innerHTML = data.attacks.map(a => `<tr><td>${a.time}</td><td>${a.ip}</td><td>${a.geo}</td><td class="alert">${a.payload}</td></tr>`).join('');
                const qrnBody = document.querySelector('#quarantine-table tbody');
                qrnBody.innerHTML = data.quarantine.map(q => `<tr><td>${q.time}</td><td>${q.url}</td><td>${q.hash}</td></tr>`).join('');
            } catch (e) { console.error("Dashboard fetch error", e); }
        }
        setInterval(fetchStats, 3000);
        fetchStats();
    </script>
</body>
</html>
"""

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def check_auth(self):
        auth_header = self.headers.get('Authorization')
        if auth_header != EXPECTED_AUTH:
            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="Tartarus SOC"')
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"401 Unauthorized")
            return False
        return True

    def do_GET(self):
        if not self.check_auth():
            return

        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode('utf-8'))
            
        elif self.path == '/api/stats':
            payload = {"attacks": [], "quarantine": []}
            
            try:
                if os.path.exists(DB_PATH):
                    with sqlite3.connect(DB_PATH) as conn:
                        cursor = conn.execute(
                            "SELECT timestamp, ip_address, geo_location, command "
                            "FROM attack_logs ORDER BY id DESC LIMIT 50"
                        )
                        for row in cursor.fetchall():
                            payload["attacks"].append({
                                "time": row[0].replace('T', ' '),
                                "ip": row[1],
                                "geo": row[2] if row[2] else "Unknown",
                                "payload": row[3]
                            })
            except Exception as e:
                logger.error(f"DB Read Error: {e}")

            try:
                if os.path.exists(QUARANTINE_LOG):
                    with open(QUARANTINE_LOG, "r", encoding="utf-8") as f:
                        lines = f.readlines()[-20:]
                        for line in lines:
                            parts = line.strip().split('|')
                            if len(parts) >= 4:
                                payload["quarantine"].append({
                                    "time": parts[0],
                                    "url": parts[1],
                                    "hash": parts[2]
                                })
            except Exception:
                pass

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(payload).encode('utf-8'))
            
        else:
            self.send_error(404)

def start_dashboard(port: int = 8080) -> None:
    try:
        server = ThreadedHTTPServer(('0.0.0.0', port), DashboardHandler)
        logger.info(f"✅ Secure SOC Dashboard active: port {port} (Protected by Basic Auth)")
        threading.Thread(target=server.serve_forever, daemon=True).start()
    except Exception as e:
        logger.error(f"Dashboard failed to start: {e}")