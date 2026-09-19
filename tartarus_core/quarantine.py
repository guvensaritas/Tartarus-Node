import os
import re
import time
import hashlib
import threading
import shutil
import urllib.request
import urllib.error
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
LOG_FILE = os.path.join(QUARANTINE_DIR, "malware_intel.log")

MAX_FILE_SIZE = 8 * 1024 * 1024
MAX_LOG_SIZE = 5 * 1024 * 1024
DOWNLOAD_TIMEOUT = 12
_lock = threading.Lock()

os.makedirs(QUARANTINE_DIR, exist_ok=True)

def _rotate_log() -> None:
    if os.path.exists(LOG_FILE) and os.path.getsize(LOG_FILE) > MAX_LOG_SIZE:
        archive_path = f"{LOG_FILE}.{int(time.time())}.bak"
        try:
            shutil.move(LOG_FILE, archive_path)
        except Exception:
            pass

def capture_payload(command: str, source_ip: str = "unknown") -> None:
    if not command:
        return

    urls = re.findall(r'https?://[^\s\'"<>\\]+', command, os.IGNORECASE) if hasattr(os, 'IGNORECASE') else re.findall(r'https?://[^\s\'"<>\\]+', command, re.IGNORECASE)

    for url in urls:
        url = url.rstrip(');,]"\'')
        _download_and_isolate(url, source_ip, command)

def _download_and_isolate(url: str, source_ip: str, original_command: str) -> None:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return

        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Accept": "*/*",
            }
        )

        with urllib.request.urlopen(req, timeout=DOWNLOAD_TIMEOUT) as response:
            payload = b""
            while len(payload) < MAX_FILE_SIZE + 1:
                chunk = response.read(8192)
                if not chunk:
                    break
                payload += chunk

            if len(payload) > MAX_FILE_SIZE:
                _write_log(source_ip, url, "SIZE_LIMIT_EXCEEDED", original_command)
                return

            if not payload:
                return

            file_hash = hashlib.sha256(payload).hexdigest()
            timestamp = int(time.time())
            safe_name = f"captured_{timestamp}_{file_hash[:12]}.infected"
            safe_path = os.path.join(QUARANTINE_DIR, safe_name)

            with open(safe_path, "wb") as f:
                f.write(b"\x00\x00HONEYPOT\x00\x00")
                f.write(payload)

            try:
                os.chmod(safe_path, 0o644)
            except Exception:
                pass

            _write_log(
                source_ip=source_ip,
                url=url,
                status="CAPTURED",
                command=original_command,
                file_hash=file_hash,
                size=len(payload),
                filename=safe_name
            )

    except urllib.error.HTTPError as e:
        _write_log(source_ip, url, f"HTTP_ERROR_{e.code}", original_command)
    except urllib.error.URLError as e:
        _write_log(source_ip, url, f"URL_ERROR_{str(e.reason)[:80]}", original_command)
    except Exception as e:
        _write_log(source_ip, url, f"UNEXPECTED_{type(e).__name__}", original_command)

def _write_log(source_ip: str, url: str, status: str, command: str,
               file_hash: str = "-", size: int = 0, filename: str = "-") -> None:
    _rotate_log()
    log_line = (
        f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
        f"IP={source_ip} | Status={status} | "
        f"SHA256={file_hash} | Size={size} | "
        f"File={filename} | URL={url} | CMD={command[:200]}\n"
    )

    with _lock:
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(log_line)
        except Exception:
            pass