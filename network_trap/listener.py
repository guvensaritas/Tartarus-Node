import socket
import threading
import time
import logging
import json
from tartarus_core.rate_limiter import register_request, check_ip_blocked
from tartarus_core.llm_bridge import SecureLLMBridge
from state_memory.tracker import log_attack

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("Tartarus_Listener")

try:
    with open("config.json", "r") as f:
        config = json.load(f)
except FileNotFoundError:
    config = {}

llm_bridge = SecureLLMBridge(config)

def handle_client(client_socket: socket.socket, client_address: tuple) -> None:
    ip_address = client_address[0]
    
    if check_ip_blocked(ip_address):
        client_socket.close()
        return

    if register_request(ip_address):
        client_socket.close()
        return

    try:
        client_socket.settimeout(120.0)
        
        # Standart SSH akışı için önce istemcinin bağlantı kurmasını simüle ediyoruz
        client_socket.sendall(b"SSH-2.0-OpenSSH_9.2p1 Ubuntu-1ubuntu1.12\n")
        client_banner = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
        
        client_socket.sendall(b"login: ")
        username = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
        
        client_socket.sendall(b"Password: ")
        pass_received = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
        
        log_attack(ip_address, f"LOGIN: user={username} pass={pass_received}")
        
        client_socket.sendall(b"\nWelcome to Ubuntu 22.04.3 LTS\n\n")
        client_socket.sendall(b"root@prod:~# ")
        
        while True:
            command = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
            if not command:
                break
                
            if command.lower() in ("exit", "quit", "logout"):
                client_socket.sendall(b"Connection closed by foreign host.\n")
                break
                
            log_attack(ip_address, command)
            
            response = llm_bridge.get_terminal_response(command)
            
            if response:
                output = f"{response}\nroot@prod:~# "
            else:
                output = "root@prod:~# "
                
            client_socket.sendall(output.encode('utf-8'))
            
    except Exception as e:
        logger.error(f"[{ip_address}] Hata: {str(e)}")
    finally:
        client_socket.close()

def start_server(port: int) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', port))
    server.listen(5)
    
    print(f"✅ SSH Honeypot aktif: port {port}")
    
    while True:
        client_socket, client_address = server.accept()
        threading.Thread(target=handle_client, args=(client_socket, client_address), daemon=True).start()