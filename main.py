import os
import json
import threading
import sys
import signal
from tartarus_core.dashboard import start_dashboard
from state_memory.tracker import init_db
from network_trap.listener import start_server

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")

def signal_handler(sig, frame):
    sys.exit(0)

def load_config() -> dict:
    if not os.path.exists(CONFIG_PATH):
        sys.exit(1)
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def main() -> None:
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    init_db()
    config = load_config()
    
    dashboard_port = config.get("dashboard_port", 8080)
    start_dashboard(port=dashboard_port)

    listen_ports = config.get("listen_ports", [2222])
    threads = []
    
    for port in listen_ports:
        t = threading.Thread(target=start_server, args=(port,), daemon=True)
        t.start()
        threads.append(t)

    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()