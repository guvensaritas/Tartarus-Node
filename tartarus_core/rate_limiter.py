import time
import threading
from collections import deque
import sqlite3
import os

_request_tracker = {}
_tracker_lock = threading.Lock()
_blocked_ips = {}

MAX_REQUESTS = 25
TIME_WINDOW = 10
BLOCK_DURATION = 60
DB_PATH = "state_memory/state_memory.db"

def _init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS banned_ips 
                        (ip TEXT PRIMARY KEY, unblock_time REAL)''')
        
        cursor = conn.execute("SELECT ip, unblock_time FROM banned_ips")
        for ip, unblock_time in cursor.fetchall():
            if time.time() < unblock_time:
                _blocked_ips[ip] = unblock_time

_init_db()

def _save_ban_to_db(ip: str, unblock_time: float):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("INSERT OR REPLACE INTO banned_ips (ip, unblock_time) VALUES (?, ?)", 
                         (ip, unblock_time))
    except Exception:
        pass

def check_ip_blocked(ip_address: str) -> bool:
    current_time = time.time()
    with _tracker_lock:
        if ip_address in _blocked_ips:
            if current_time < _blocked_ips[ip_address]:
                return True
            else:
                del _blocked_ips[ip_address]
                try:
                    with sqlite3.connect(DB_PATH) as conn:
                        conn.execute("DELETE FROM banned_ips WHERE ip = ?", (ip_address,))
                except Exception:
                    pass
        return False

def register_request(ip_address: str) -> bool:
    current_time = time.time()
    
    with _tracker_lock:
        if ip_address not in _request_tracker:
            _request_tracker[ip_address] = deque() 
        
        timestamps = _request_tracker[ip_address]
        window_start = current_time - TIME_WINDOW
        
        # Süresi dolan eski istekleri temizle (sağ taraftan pop edilir)
        while timestamps and timestamps[-1] < window_start:
            timestamps.pop()
            
        # Yeni isteği sol tarafa ekle
        timestamps.appendleft(current_time)
        
        # İstek limiti aşıldı mı kontrol et
        if len(timestamps) > MAX_REQUESTS:
            unblock_time = current_time + BLOCK_DURATION
            _blocked_ips[ip_address] = unblock_time
            
            # Takip listesinden temizle
            del _request_tracker[ip_address] 
            
            # Veritabanına işle
            _save_ban_to_db(ip_address, unblock_time)
            
            return True # Engellendi
            
        return False # Devam edebilir