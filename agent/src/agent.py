#!/usr/bin/python3
"""
🛡️ FIM AGENT
==========================

⚠ DISCLAIMER:
This script is provided for portfolio and showcase purposes only. Actual production configurations, credentials, and infrastructure details are managed securely and are not included in this repository.

It demonstrates the design and logic of a File Integrity Monitoring (FIM)
agent, including audit correlation and malware scanning workflows.

It is NOT intended to be deployed as-is in a production environment.
Additional hardening, validation, access control, and testing are required
before any real-world use.

Author: Ichramsyah
"""

import sys
import os
from datetime import datetime
import subprocess
import pwd
import re
import time
import requests
import hashlib 
import yara
from pathlib import Path

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
API_BASE_URL = os.getenv("API_URL", "http://127.0.0.1:8000/api")
API_INGEST_URL = f"{API_BASE_URL}/ingest/fim/"
YARA_RULES_PATH = os.getenv("YARA_PATH", os.path.join(BASE_DIR, "rules", "yara-rules.yar"))
DEBUG_LOG_FILE = os.getenv("LOG_FILE", "/var/log/fim_agent.log")
CACHE_DIR = "/tmp/fim_agent_cache"

# --- BUSINESS LOGIC CONFIG ---
OFFICE_HOURS_START = 6
OFFICE_HOURS_END = 18

WHITELIST_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.mp4', 
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', 
    '.css', '.xml', '.json', '.txt'
}
BLACKLIST_EXTENSIONS = {
    '.php', '.phtml', '.php3', '.php4', '.php5', '.php7', 
    '.sh', '.cgi', '.pl', '.exe', '.js', '.py', '.bash'
}
WHITELIST_PATHS = ['/var/www/OJS/public/']
EXCLUDED_PATHS = [
    '/var/www/OJS/cache/', '/var/log/', '/proc/', '/sys/', '/dev/', 
    '/.git/', '/node_modules/', '/venv/'
]

# --- GLOBAL YARA INITIALIZATION ---
try:
    if os.path.exists(YARA_RULES_PATH):
        YARA_RULES = yara.compile(filepath=YARA_RULES_PATH)
    else:
        YARA_RULES = None
except Exception as e:
    YARA_RULES = None
    print(f"Warning: Failed to compile YARA rules: {e}")

# --- UTILS ---
def ensure_dir(path):
    if not os.path.exists(path):
        try: os.makedirs(path)
        except: pass

ensure_dir(CACHE_DIR)

def write_debug_log(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        with open(DEBUG_LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {message}\n")
    except PermissionError:
        print(f"[ERROR] Permission denied writing to log: {message}")
    except Exception: pass 

def check_deduplication(file_path, event):
    """Mencegah spam alert yang sama dalam waktu singkat (1.5 detik)"""
    try:
        unique_str = f"{file_path}_{event}"
        file_hash = hashlib.md5(unique_str.encode()).hexdigest()
        cache_file = os.path.join(CACHE_DIR, file_hash)
        now = time.time()
        
        if os.path.exists(cache_file):
            if now - os.path.getmtime(cache_file) < 1.5: 
                return False 
        
        with open(cache_file, 'w') as f:
            f.write(str(now))
        return True
    except: return True

def send_to_api(payload):
    try:
        headers = {'Content-Type': 'application/json'}
        response = requests.post(API_INGEST_URL, json=payload, headers=headers, timeout=5)
        
        if response.status_code != 201:
            write_debug_log(f"API FAIL: {response.status_code} | {response.text}")
    except Exception as e:
        write_debug_log(f"API ERROR: {e}")

def get_audit_info(target_path):
    """
    Use `ausearch` to find the user who made the changes.
    NOTE: Requires sudoers configuration so that user script can run ausearch without password.
    """
    filename_only = os.path.basename(target_path) 
    max_retries = 3
    
    for attempt in range(max_retries):
        try:
            time.sleep(1 + attempt) 
            
            cmd_list = ["sudo", "-n", "/usr/sbin/ausearch", "-ts", "recent", "-m", "SYSCALL", "-k", "fim_ojs", "-i"]
            result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0: continue
            
            output = result.stdout.strip()
            if not output: continue

            events = output.split('----')
            relevant_event = None
            
            for evt in reversed(events):
                if target_path in evt or filename_only in evt:
                    relevant_event = evt
                    break
            
            if not relevant_event: continue 

            last_syscall = ""
            for line in relevant_event.split('\n'):
                if 'type=SYSCALL' in line:
                    last_syscall = line; break
            
            if not last_syscall: continue

            uid_match = re.search(r' uid=(\S+)', last_syscall)
            user = uid_match.group(1) if uid_match else "unknown"
            
            if user.isdigit():
                try: user = pwd.getpwuid(int(user)).pw_name
                except: pass
            
            comm_match = re.search(r' comm=(\S+)', last_syscall)
            comm = comm_match.group(1).strip('"') if comm_match else "unknown"
            
            cwd_match = re.search(r' cwd=(\S+)', relevant_event)
            exe = cwd_match.group(1).strip('"') if cwd_match else "unknown"

            process_info = f"{comm} -> {exe}" if exe != "unknown" else comm
            return user, process_info
            
        except subprocess.TimeoutExpired:
            return "timeout", "timeout"
        except Exception: 
            return "error", "error"
            
    return "unknown", "unknown"

def scan_malware(file_path):
    """Scan files using YARA rules that were compiled at the beginning."""
    try:
        if not YARA_RULES: return None
        if not os.path.exists(file_path) or os.path.getsize(file_path) == 0: return None
        
        matches = YARA_RULES.match(file_path)
        if matches:
            return matches[0].rule
    except Exception as e:
        write_debug_log(f"YARA SCAN ERROR: {e}")
    return None

def process_event(full_path, activity_type):
    clean_path = os.path.normpath(full_path.strip())

    is_delete = False
    action_str = activity_type

    if "IN_DELETE" in activity_type or "IN_MOVED_FROM" in activity_type:
        action_str = "DIHAPUS"
        is_delete = True
    elif "IN_CREATE" in activity_type or "IN_MOVED_TO" in activity_type:
        action_str = "DITAMBAHKAN"
    elif "IN_CLOSE_WRITE" in activity_type:
        action_str = "DIUBAH"
    
    if not check_deduplication(clean_path, action_str): return 
    for excluded in EXCLUDED_PATHS:
        if clean_path.startswith(excluded): return

    filename = os.path.basename(clean_path)
    
    if filename.startswith('.') and (filename.endswith('.swp') or filename.endswith('.tmp')): return
    
    _, ext = os.path.splitext(clean_path)
    ext = ext.lower()

    is_critical_file = (filename == '.htaccess' or ext in BLACKLIST_EXTENSIONS)

    current_hour = datetime.now().hour
    is_after_hours = not (OFFICE_HOURS_START <= current_hour < OFFICE_HOURS_END)

    if not is_after_hours:
        if not is_critical_file:
            for safe_path in WHITELIST_PATHS:
                if clean_path.startswith(safe_path): return
            if ext in WHITELIST_EXTENSIONS: return

    severity = "Normal"
    malware_name = None
    
    if not is_delete:
        malware_name = scan_malware(clean_path)

    if malware_name:
        severity = f"[MALWARE] {malware_name}"
    elif is_critical_file: 
        severity = "[BAHAYA]"
    elif is_after_hours:
        severity = "[KEGIATAN MENCURIGAKAN]"

    user_actor, process_actor = get_audit_info(clean_path)
    
    actor_info = f" oleh {user_actor} ({process_actor})" if user_actor != "unknown" else ""
    log_message = f"{severity + ' ' if severity != 'Normal' else ''}{action_str}: {clean_path}{actor_info}"
    
    write_debug_log(f"ALERT: {log_message}")

    payload = {
        "severity": severity,
        "action": action_str,
        "path": clean_path,
        "user": user_actor,
        "process": process_actor,
        "full_log": log_message
    }

    send_to_api(payload)

if __name__ == "__main__":
    if len(sys.argv) > 2:
        process_event(sys.argv[1], sys.argv[2])