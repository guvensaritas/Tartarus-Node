import json
import os
import urllib.request
import urllib.error
import re
import logging
import threading
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Tartarus_LLM_Bridge")

class SecureLLMBridge:
    def __init__(self, config):
        self.api_url = config.get("ollama", {}).get("api_url", "http://127.0.0.1:11434/api/generate")
        self.model = config.get("ollama", {}).get("model", "huihui_ai/qwen3-abliterated:8b")
        self.timeout = config.get("ollama", {}).get("timeout", 10)
        self.max_tokens = config.get("ollama", {}).get("max_tokens", 1024)
        
        self.system_prompt = (
            "You are a fully simulated Ubuntu 22.04 LTS bash terminal. "
            "Do not execute any real commands. Return only text. "
            "If the command is invalid, return an error in the format 'bash: {command}: command not found'. "
            "If commands like su, rm, wget, curl, chmod, chown, export are used, return 'Permission denied'. "
            "Always end with 'root@ubuntu:~# '. "
            "No explanations, no markdown, no backticks, no code blocks."
        )

    def _safe_sanitize(self, command: str) -> str:
        if not command or len(command) > 500:
            return ""
        
        command = re.sub(r'[^a-zA-Z0-9_\-\.\s\/\=\:\;\$\^\&\%\@\*\(\)\{\}\[\]\|\<\>\'\"]', '', command)
        command = re.sub(r'(\|\||\&\&|;|\|\|)', '', command) 
        
        if len(command) > 300:
            command = command[:300]
        
        return command.strip()

    def get_terminal_response(self, attacker_command: str) -> str:
        safe_command = self._safe_sanitize(attacker_command)
        
        if not safe_command:
            return "bash: command not found\nroot@ubuntu:~# "
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": f"Execute this command: {safe_command}"}
            ],
            "stream": False,
            "options": {
                "temperature": 0.0,
                "top_p": 0.8,
                "top_k": 30,
                "num_predict": self.max_tokens
            }
        }
        
        try:
            req = urllib.request.Request(
                self.api_url,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'}
            )
            
            with urllib.request.urlopen(req, timeout=self.timeout) as response:
                result = json.loads(response.read().decode('utf-8'))
                raw_output = result.get("message", {}).get("content", "")
                
                safe_output = re.sub(r'```[\s\S]*?```', '', raw_output, flags=re.MULTILINE)
                safe_output = re.sub(r'root@ubuntu:~#.*$', '', safe_output).strip()
                
                if not safe_output:
                    return "bash: command not found\nroot@ubuntu:~# "
                
                return safe_output + "\nroot@ubuntu:~# "
                
        except urllib.error.URLError:
            logger.warning(f"LLM API connection error: {self.api_url}")
            return "bash: command not found\nroot@ubuntu:~# "
        except Exception as e:
            logger.error(f"LLM Bridge Critical Error: {str(e)}")
            return "Segmentation fault (core dumped)\nroot@ubuntu:~# "