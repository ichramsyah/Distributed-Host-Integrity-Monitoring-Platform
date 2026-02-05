"""
📂 UTILITY: LEGACY LOG IMPORTER
===============================
Description:
  A migration tool to ingest old flat-file logs (TXT) into the new FimLog database.
  Useful for initial system setup or restoring historical data.

Usage:
  python manage.py import_legacy_logs --file /path/to/fim_log.txt
"""

from django.core.management.base import BaseCommand
from api.models import FimLog
import re
import os
from datetime import datetime
from django.utils.timezone import make_aware

class Command(BaseCommand):
    help = 'Import legacy logs from a text file into the database'

    def add_arguments(self, parser):
        parser.add_argument(
            '--file', 
            type=str, 
            help='Full path to the legacy log file',
            required=True
        )

    def handle(self, *args, **kwargs):
        log_file_path = kwargs['file']

        if not os.path.exists(log_file_path):
            self.stdout.write(self.style.ERROR(f"Error: File {log_file_path} not found."))
            return

        self.stdout.write(f"[*] Starting import from {log_file_path}...")
        
        count = 0
        success_count = 0
        
        log_pattern = re.compile(
            r'^\[(.*?)\]\s+'          
            r'(.*?):\s+'                
            r'(.*?)'                    
            r'(?:\s+(oleh .*))?$'      
        )
        pelaku_pattern = re.compile(r'oleh\s(.*?)\s\(via\s(.*?)(?:\s->\s(.*?))?\)')

        try:
            with open(log_file_path, 'r', encoding='utf-8') as f:
                batch_logs = []

                for line in f:
                    line = line.strip()
                    if not line: continue

                    match = log_pattern.match(line)
                    if not match:
                        continue

                    try:
                        timestamp_str = match.group(1)
                        tag_and_action = match.group(2).strip()
                        path = match.group(3).strip()
                        info_pelaku_raw = match.group(4)

                        dt_obj = datetime.strptime(timestamp_str, '%d-%m-%Y %H:%M:%S')
                        dt_obj = make_aware(dt_obj) 
                        
                        severity = "NORMAL" 
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

                        # Prepare Object
                        log_entry = FimLog(
                            timestamp=dt_obj, 
                            severity=severity,
                            action=action,
                            path=path,
                            user=user,
                            process=process,
                            full_log=line
                        )
                        batch_logs.append(log_entry)
                        count += 1
                        
                        if len(batch_logs) >= 500:
                            FimLog.objects.bulk_create(batch_logs)
                            success_count += len(batch_logs)
                            batch_logs = []
                            self.stdout.write(f"Processed {success_count} logs...")

                    except Exception as e:
                        self.stdout.write(self.style.WARNING(f"Skipping line due to error: {e}"))

                # Insert sisa data
                if batch_logs:
                    FimLog.objects.bulk_create(batch_logs)
                    success_count += len(batch_logs)

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Critical Error: {e}"))

        self.stdout.write(self.style.SUCCESS(f"✔ DONE! Successfully imported {success_count} logs."))