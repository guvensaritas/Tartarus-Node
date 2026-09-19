# Tartarus-Node

Enterprise-grade, zero-dependency AI honeypot and dynamic deception network powered by local Large Language Models (Ollama).

## Architecture

Tartarus-Node is engineered for high-interaction threat deception, isolating attackers in a simulated terminal environment while safely capturing malicious payloads and streaming real-time telemetry to a local SOC dashboard.

```text
[Attacker] ---> (TCP Ports) ---> [Listener / Firewall] ---> [Mirage Engine (Qwen)]
                                         |
                                         v
                           [Quarantine / SIEM Tracker] ---> [SOC Dashboard]
                           Core Modules
main.py: Central orchestrator managing signal handlers, database initialization, and concurrent multi-port socket threads.

network_trap/: Multi-port TCP concurrent listener equipped with active rate-limiting and dynamic IP quarantine firewall.

tartarus_core/llm_bridge.py: Mirage Engine interfacing with local Ollama models for zero-safety-refusal interactive command simulation.

tartarus_core/quarantine.py: Advanced payload isolation engine parsing URLs, enforcing strict size limits, and neutralizing binaries with honeypot headers.

state_memory/: SQLite-backed attack telemetry logger exporting SIEM JSON alerts and triggering automated webhook notifications.

tartarus_core/dashboard.py: Zero-dependency embedded HTTP SOC dashboard providing real-time attack visualization.

Quick Start
Ensure Ollama is running locally with the target model:

Bash
ollama run huihui_ai/qwen3-abliterated:8b
Clone the repository and configure your settings:

Bash
cp config.json.example config.json
Launch the deception framework:

Bash
python main.py
License
Distributed under the MIT License. See LICENSE for more information.