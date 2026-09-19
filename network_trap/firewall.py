import time
import threading

_request_tracker = {}
_tracker_lock = threading.Lock()
MAX_REQUESTS = 25
TIME_WINDOW = 10
BLOCK_DURATION = 60
_blocked_ips = {}

def check_ip_blocked(ip_address: str) -> bool:
    current_time = time.time()
    with _tracker_lock:
        if ip_address in _blocked_ips:
            if current_time < _blocked_ips[ip_address]:
                return True
            del _blocked_ips[ip_address]
        return False

def register_request(ip_address: str) -> bool:
    current_time = time.time()
    with _tracker_lock:
        if ip_address not in _request_tracker:
            _request_tracker[ip_address] = []
        
        timestamps = _request_tracker[ip_address]
        timestamps[:] = [t for t in timestamps if current_time - t < TIME_WINDOW]
        
        if len(timestamps) >= MAX_REQUESTS:
            _blocked_ips[ip_address] = current_time + BLOCK_DURATION
            return True
            
        timestamps.append(current_time)
        return False