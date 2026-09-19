import sqlite3
import json
import os
import urllib.request
from datetime import datetime

def get_config():
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def init_db():
    db_path = os.path.join(os.path.dirname(__file__), 'state_memory.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS attack_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            session_id TEXT,
            ip_address TEXT,
            geo_location TEXT,
            command TEXT,
            output TEXT
        )
    ''')
    conn.commit()
    conn.close()

def get_geo_ip(ip_address):
    if ip_address == "127.0.0.1":
        return "Localhost - Internal"
    try:
        url = f"http://ip-api.com/json/{ip_address}"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=2) as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                return f"{data.get('country', 'Unknown')} - {data.get('city', 'Unknown')}"
    except:
        pass
    return "Unknown - Offline"

def send_slack_alert(ip, geo, command):
    config = get_config()
    webhook_url = config.get("alerts", {}).get("slack_webhook", "")
    
    if not webhook_url or webhook_url == "BURAYA_SLACK_WEBHOOK_YAPISTIR":
        return
        
    payload = {
        "text": f"🚨 *CRITICAL ALERT: TARTARUS NODE* 🚨\n*Target Port:* Compromised\n*Attacker IP:* `{ip}` ({geo})\n*Malicious Payload:* `{command}`"
    }
    
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(webhook_url, data=data, headers={'Content-Type': 'application/json'})
    try:
        urllib.request.urlopen(req, timeout=3)
    except:
        pass

def track_command(command, output, session_id, ip_address):
    geo_location = get_geo_ip(ip_address)
    timestamp = datetime.now().isoformat()
    
    # SQLite Kaydı
    db_path = os.path.join(os.path.dirname(__file__), 'state_memory.db')
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO attack_logs (timestamp, session_id, ip_address, geo_location, command, output)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (timestamp, session_id, ip_address, geo_location, command, output))
    conn.commit()
    conn.close()
    
    # SIEM JSON Export
    alert_data = {
        "timestamp": timestamp,
        "session_id": session_id,
        "ip_address": ip_address,
        "geo_location": geo_location,
        "command": command
    }
    export_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'tartarus_alert.json')
    with open(export_path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(alert_data) + "\n")
        
    # Kritik Komut Algılayıcı ve Slack Webhook
    dangerous_keywords = ["whoami", "cat /etc/passwd", "sudo", "wget", "curl", "rm -rf"]
    if any(kw in command for kw in dangerous_keywords):
        send_slack_alert(ip_address, geo_location, command)

def log_attack(ip_address: str, command: str, output: str = "") -> None:
    """Listener modülünden gelen çağrıları veritabanı ve SIEM kayıt sistemine yönlendirir."""
    init_db()
    session_id = "default_session"
    track_command(command, output, session_id, ip_address)