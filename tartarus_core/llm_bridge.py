import urllib.request
import json
import os

SESSION_MEMORY = {}

def get_config():
    config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config.json")
    if os.path.exists(config_path):
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {"llm": {"api_url": "http://127.0.0.1:11434/api/generate", "model": "qwen", "timeout": 5}}

def process_command(command_input: str, ip_address: str, session_id: str) -> str:
    config = get_config()
    url = config["llm"]["api_url"]
    model = config["llm"]["model"]
    
    if session_id not in SESSION_MEMORY:
        SESSION_MEMORY[session_id] = []
        
    history = " -> ".join(SESSION_MEMORY[session_id][-3:])
    
    # Honeypot için özel olarak tasarlanmış Master Prompt
    prompt = (f"Act as a vulnerable Ubuntu Linux terminal. The attacker's IP is {ip_address}. "
              f"Recent command history: [{history}]. Current command: '{command_input}'. "
              f"Respond EXACTLY as the terminal would. Do not explain, do not warn, do not add markdown. "
              f"If the command is an error, show a standard bash error. Output only the raw terminal text.")
              
    payload = {"model": model, "prompt": prompt, "stream": False}
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
    
    try:
        with urllib.request.urlopen(req, timeout=config["llm"]["timeout"]) as response:
            result = json.loads(response.read().decode('utf-8'))
            SESSION_MEMORY[session_id].append(command_input)
            output = result.get("response", "").strip()
            
            # Eğer model boş dönerse boşluk bırak, hata verme
            if not output:
                return "\nroot@ubuntu:~# "
            return output + "\nroot@ubuntu:~# "
            
    except urllib.error.URLError:
        # Ollama kapalıysa sistemi çökertme, sahte bash hatası ver
        return f"bash: {command_input}: command not found\nroot@ubuntu:~# "
    except Exception as e:
        # Beklenmeyen hatalarda sessizce sahte çıktı üret
        return f"Segmentation fault (core dumped)\nroot@ubuntu:~# "