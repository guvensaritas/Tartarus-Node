import socket
import threading
import time
from tartarus_core.llm_bridge import process_command
from state_memory.tracker import log_attack
from network_trap.firewall import check_ip_blocked, register_request

def handle_client(client_socket: socket.socket, client_address: tuple) -> None:
    ip_address = client_address[0]
    
    if check_ip_blocked(ip_address):
        client_socket.close()
        return

    if register_request(ip_address):
        client_socket.close()
        return

    session_id = f"{ip_address}_{int(time.time())}"
    
    try:
        client_socket.sendall(b"login: ")
        banner_received = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
        
        client_socket.sendall(b"Password: ")
        pass_received = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
        
        log_attack(ip_address, f"LOGIN ATTEMPT: user={banner_received} pass={pass_received}")
        
        client_socket.sendall(b"\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-88-generic x86_64)\n\n")
        client_socket.sendall(b"root@prod-db-server:~# ")
        
        while True:
            command = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
            if not command:
                break
                
            if command.lower() in ("exit", "quit"):
                client_socket.sendall(b"Connection closed by foreign host.\n")
                break
                
            log_attack(ip_address, command)
            
            response = process_command(command, ip_address, session_id)
            client_socket.sendall(response.encode('utf-8'))
            
    except Exception:
        pass
    finally:
        client_socket.close()

def start_server(port: int) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(('0.0.0.0', port))
        server.listen(5)
        
        while True:
            client_socket, client_address = server.accept()
            client_thread = threading.Thread(
                target=handle_client, 
                args=(client_socket, client_address), 
                daemon=True
            )
            client_thread.start()
    except Exception:
        server.close()