#!/usr/bin/python3
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

# --- KONFIGURASI ---
HOME_DIR = "/home/ichram"
API_BASE_URL = "http://127.0.0.1:5000/api"
API_INGEST_URL = f"{API_BASE_URL}/ingest/fim/"
YARA_RULES_PATH = os.path.join(HOME_DIR, "fim", "yara-rules.yar")
DEBUG_LOG_FILE = os.path.join(HOME_DIR, "fim", "agent_debug.txt")
CACHE_DIR = "/tmp/fim_cache"

if not os.path.exists(CACHE_DIR):
    try: os.makedirs(CACHE_DIR)
    except: pass

# --- FILTER ---
JAM_AWAL_MALAM = 18
JAM_AKHIR_MALAM = 6
WHITELIST_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.svg', '.mp4', '.mov', '.avi', '.webm', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.css', '.xml', '.json', '.txt']
BLACKLIST_EXTENSIONS = ['.php', '.phtml', '.php3', '.php4', '.php5', '.php7', '.sh', '.cgi', '.pl', '.exe', '.js', '.py']
WHITELIST_PATHS = ['/var/www/OJS/public/']
EXCLUDED_PATHS = ['/var/www/OJS/cache/', '/var/log/', '/proc/', '/sys/', '/dev/', f'{HOME_DIR}/.bash_history', f'{HOME_DIR}/.gitconfig', f'{HOME_DIR}/fim/', f'{HOME_DIR}/.ssh/', f'{HOME_DIR}/.cache/', f'{HOME_DIR}/.local/', f'{HOME_DIR}/logs/']

def tulis_log_debug(pesan):
    timestamp = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
    try:
        os.makedirs(os.path.dirname(DEBUG_LOG_FILE), exist_ok=True)
        with open(DEBUG_LOG_FILE, "a") as f:
            f.write(f"[{timestamp}] {pesan}\n")
    except: pass 

def cek_deduplikasi(path_file, event):

    try:
        unique_str = f"{path_file}_{event}"
        file_hash = hashlib.md5(unique_str.encode()).hexdigest()
        cache_file = os.path.join(CACHE_DIR, file_hash)
        sekarang = time.time()
        
        if os.path.exists(cache_file):
            if sekarang - os.path.getmtime(cache_file) < 1.5: 
                return False 
        
        with open(cache_file, 'w') as f:
            f.write(str(sekarang))
        return True
    except: return True

def kirim_ke_api(data_payload):
    try:
        response = requests.post(API_INGEST_URL, json=data_payload, timeout=5)
        if response.status_code != 201:
            tulis_log_debug(f"GAGAL API: {response.status_code} | {response.text}")
    except Exception as e:
        tulis_log_debug(f"ERROR API: {e}")

def ambil_info_audit(path_file):
    target_path = path_file 
    filename_only = os.path.basename(target_path) 
    max_retries = 3
    for attempt in range(max_retries):
        try:
            time.sleep(1 + (attempt * 1)) 
            cmd_list = ["sudo", "-n", "/usr/sbin/ausearch", "-ts", "recent", "-m", "SYSCALL", "-k", "fim_ojs", "-i"]
            result = subprocess.run(cmd_list, capture_output=True, text=True, timeout=8)
            
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
        except: return "error", "error"
    return "unknown", "unknown"

def scan_malware(path_file):
    try:
        if not os.path.exists(YARA_RULES_PATH): return None
        if not os.path.exists(path_file) or os.path.getsize(path_file) == 0: return None
        rules = yara.compile(filepath=YARA_RULES_PATH)
        matches = rules.match(path_file)
        if matches: return matches[0].rule
    except: pass
    return None

def process_event(path_lengkap, jenis_aktivitas):
    path_bersih = os.path.normpath(path_lengkap.strip())

    # --- 1. MAPPING EVENT KE LABEL (LEBIH AKURAT) ---
    is_delete = False
    aktivitas_string = jenis_aktivitas

    if "IN_DELETE" in jenis_aktivitas or "IN_MOVED_FROM" in jenis_aktivitas:
        aktivitas_string = "DIHAPUS"
        is_delete = True
    elif "IN_CREATE" in jenis_aktivitas or "IN_MOVED_TO" in jenis_aktivitas:
        aktivitas_string = "DITAMBAHKAN"
    elif "IN_CLOSE_WRITE" in jenis_aktivitas:
        aktivitas_string = "DIUBAH"
    
    if not cek_deduplikasi(path_bersih, aktivitas_string):
        return 

    # --- 3. EXCLUSION ---
    for excluded in EXCLUDED_PATHS:
        if path_bersih.startswith(excluded): return

    nama_file = os.path.basename(path_bersih)
    if nama_file.startswith('.') and (nama_file.endswith('.swp') or nama_file.endswith('.tmp')): return
    
    _, file_extension = os.path.splitext(path_bersih)
    file_extension = file_extension.lower()

    # --- 4. KRITIKAL CHECK ---
    is_critical_file = (nama_file == '.htaccess' or file_extension in BLACKLIST_EXTENSIONS)

    # --- 5. FILTER TIME & WHITELIST ---
    sekarang_jam = datetime.now().hour
    di_luar_jam_kerja = False
    if JAM_AWAL_MALAM > JAM_AKHIR_MALAM:
        if sekarang_jam >= JAM_AWAL_MALAM or sekarang_jam < JAM_AKHIR_MALAM: di_luar_jam_kerja = True
    else:
        if JAM_AWAL_MALAM <= sekarang_jam < JAM_AKHIR_MALAM: di_luar_jam_kerja = True

    if not di_luar_jam_kerja:
        if not is_critical_file:
            for safe_path in WHITELIST_PATHS:
                if path_bersih.startswith(safe_path): return
            if file_extension in WHITELIST_EXTENSIONS: return

    # --- 6. SEVERITY & YARA ---
    severity_tag = "Normal"
    nama_malware = None
    
    if not is_delete:
        nama_malware = scan_malware(path_bersih)

    if nama_malware:
        severity_tag = "[MALWARE]"
    elif is_critical_file: 
        severity_tag = "[BAHAYA]"
    elif di_luar_jam_kerja:
        severity_tag = "[KEGIATAN MENCURIGAKAN]"

    tulis_log_debug(f"Event: {jenis_aktivitas} -> {aktivitas_string} | Path: {path_bersih} | Sev: {severity_tag}")

    user_pelaku, proses_pelaku = ambil_info_audit(path_bersih)
    info_pelaku_str = f" oleh {user_pelaku} ({proses_pelaku})" if user_pelaku != "unknown" else ""

    data_payload = {
        "severity": severity_tag,
        "action": aktivitas_string,
        "path": path_bersih,
        "user": user_pelaku,
        "process": proses_pelaku,
        "full_log": f"{severity_tag + ' ' if severity_tag != 'Normal' else ''}{aktivitas_string}: {path_bersih}{info_pelaku_str}"
    }

    kirim_ke_api(data_payload)

if __name__ == "__main__":
    if len(sys.argv) > 2:
        process_event(sys.argv[1], sys.argv[2])