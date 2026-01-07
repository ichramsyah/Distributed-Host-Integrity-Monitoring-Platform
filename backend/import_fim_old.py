import os
import sys
import django
import re
from datetime import datetime

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'backend.settings')
django.setup()

from api.models import FimLog

OLD_LOG_FILE = '/home/webadm1/fim_log.txt' 

def parse_and_save():
    if not os.path.exists(OLD_LOG_FILE):
        print(f"Error: File {OLD_LOG_FILE} tidak ditemukan.")
        return

    print(f"Mulai mengimpor data dari {OLD_LOG_FILE}...")
    
    count = 0
    
    log_pattern = re.compile(
        r'^\[(.*?)\]\s+'           
        r'(.*?):\s+'                
        r'(.*?)'                    
        r'(?:\s+(oleh .*))?$'      
    )
    
    pelaku_pattern = re.compile(r'oleh\s(.*?)\s\(via\s(.*?)(?:\s->\s(.*?))?\)')

    with open(OLD_LOG_FILE, 'r', encoding='utf-8') as f:

        for line in f:
            line = line.strip()
            if not line: continue

            match = log_pattern.match(line)
            if not match:
                print(f"Skipping unparseable line: {line}")
                continue

            try:
                timestamp_str = match.group(1)
                tag_and_action = match.group(2).strip()
                path = match.group(3).strip()
                info_pelaku_raw = match.group(4)

                dt_obj = datetime.strptime(timestamp_str, '%d-%m-%Y %H:%M:%S')
                
                severity = "Normal"
                action = tag_and_action
                
                if tag_and_action.startswith('['):
                    end_bracket = tag_and_action.find(']')
                    if end_bracket != -1:
                        severity = tag_and_action[1:end_bracket] 
                        action = tag_and_action[end_bracket+1:].strip() 

                user = "unknown"
                process = "unknown"
                
                if info_pelaku_raw:
                    p_match = pelaku_pattern.search(info_pelaku_raw)
                    if p_match:
                        user = p_match.group(1)
                        comm = p_match.group(2)
                        exe = p_match.group(3)
                        
                        process = comm
                        if exe:
                            process = f"{comm} -> {os.path.basename(exe)}"

                log_entry = FimLog(
                    timestamp=dt_obj, 
                    severity=severity,
                    action=action,
                    path=path,
                    user=user,
                    process=process,
                    full_log=line
                )
                log_entry.save()
                
                FimLog.objects.filter(id=log_entry.id).update(timestamp=dt_obj)
                
                count += 1
                if count % 100 == 0:
                    print(f"Sudah mengimpor {count} data...")

            except Exception as e:
                print(f"Gagal memproses baris: {line} | Error: {e}")

    print(f"SELESAI! Total {count} log berhasil diimpor ke database.")

if __name__ == '__main__':
    parse_and_save()
