# Tartarus-Node (AegisBlue) 🛡️

**Advanced LLM-Powered Cybersecurity Honeypot & Deception Engine**

Tartarus-Node is a production-ready, highly interactive deception system designed to act as an intelligent SSH honeypot. By bridging network intrusion attempts with an isolated Local Large Language Model (LLM), it dynamically analyzes, engages, and logs attacker behavior in real-time.

## ⚡ Core Architecture & Security Features

* **LLM-Driven Deception:** Utilizes Ollama (`qwen3-abliterated:8b`) to generate dynamic, context-aware terminal responses, trapping attackers in endless loops.
* **Zero-Dependency Core:** Built entirely on Python's standard library. No external pip packages required, ensuring zero supply-chain vulnerabilities.
* **Military-Grade Hardening:** 
  * Multi-stage Docker build minimizing the attack surface.
  * Strict non-root execution (`appuser`).
  * Deceptive directory permissions (`755`) allowing attackers to read decoy files while preventing malicious write/delete actions.
* **Isolated Networking:** The LLM engine and the honeypot operate on an isolated Docker bridge network, unreachable from the public internet.
* **SOC Dashboard:** A built-in, HTTP Basic Auth protected monitoring dashboard running on a dedicated port.

## 🚀 Deployment (Production)

### 1. Prerequisites
Ensure you have Docker and Docker Compose installed on your host machine.

### 2. Configuration
Clone the repository and prepare your environment configuration:

```bash
git clone https://github.com/guvensaritas/tartarus-node.git
cd tartarus-node
cp config.json.example config.json
```
Edit config.json to set your secure dashboard password and optional Slack webhook.

3. Ignition
Build and run the infrastructure in detached mode:

Bash
docker compose up --build -d
4. Access
Honeypot Listener: ssh root@<your-server-ip> -p 2222

SOC Dashboard: http://<your-server-ip>:8080

⚠️ Disclaimer
This project is developed strictly for defensive cybersecurity, research, and educational purposes. Do not deploy this in environments without proper network isolation and authorization.