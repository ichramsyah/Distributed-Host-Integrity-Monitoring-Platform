"""
📂 MANAGEMENT COMMAND: MONTHLY FIM LOG BACKUP
=============================================
Description:
  This script is executed via a cron job on the 1st of every month.
  It acts as a "Data Archival & Cleanup" mechanism.

Key Features:
  1. Automated Calculation: Determines the start and end date of the previous month.
  2. Data Retention Policy: Archives logs to CSV for compliance/audit.
  3. Database Optimization: Deletes archived rows to keep the 'FimLog' table lightweight.
  4. Memory Safety: Uses .iterator() to handle large datasets without RAM spikes.

Usage:
  python manage.py archive_fim_logs
"""

from django.core.management.base import BaseCommand
from api.models import FimLog
from django.conf import settings  
import csv
import os
from datetime import date, timedelta

class Command(BaseCommand):
    help = 'Backup last month\'s data to CSV and delete from database'

    def handle(self, *args, **kwargs):
        today = date.today()
        first_day_this_month = today.replace(day=1)
        last_day_prev_month = first_day_this_month - timedelta(days=1)
        first_day_prev_month = last_day_prev_month.replace(day=1)
        month_str = first_day_prev_month.strftime('%Y-%m')
        
        BACKUP_ROOT = os.getenv('BACKUP_ROOT', os.path.join(settings.BASE_DIR, 'monthly-reports'))
        
        if not os.path.exists(BACKUP_ROOT):
            os.makedirs(BACKUP_ROOT)

        self.stdout.write(f"[*] Memproses data periode: {first_day_prev_month} s.d {last_day_prev_month}")

        filename = os.path.join(BACKUP_ROOT, f"fim_log_{month_str}.csv")

        self.backup_fim(
            filename=filename,
            start_date=first_day_prev_month,
            end_date=last_day_prev_month
        )

    def backup_fim(self, filename, start_date, end_date):
        logs = FimLog.objects.filter(timestamp__date__gte=start_date, timestamp__date__lte=end_date)
        count = logs.count()

        if count == 0:
            self.stdout.write(self.style.WARNING(f"[!] Tidak ada data FimLog untuk periode ini."))
            return

        self.stdout.write(f"[*] Menemukan {count} data FimLog. Menulis ke CSV...")

        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile, delimiter=';')
                
                headers = ['Tanggal', 'Jam', 'Severity', 'User', 'Nama File', 'Action', 'Command', 'Lokasi', 'Path Lengkap']
                writer.writerow(headers)

                for log in logs.iterator():
                    nama_file = os.path.basename(log.path) if log.path else "-"
                    
                    cmd_val = log.command or '-' 
                    proc_val = log.process or '-' 
                    
                    severity_val = log.severity or 'NORMAL'

                    row = [
                        log.timestamp.strftime('%Y-%m-%d'), 
                        log.timestamp.strftime('%H:%M'),
                        severity_val,  
                        log.user or "unknown",
                        nama_file,
                        log.action,
                        cmd_val,  
                        proc_val,  
                        log.path
                    ]
                    writer.writerow(row)
            
            self.stdout.write(self.style.SUCCESS(f"[+] Sukses backup FIM ke {filename}"))

            deleted, _ = logs.delete()
            self.stdout.write(self.style.SUCCESS(f"[+] Berhasil menghapus {deleted} data FimLog dari database."))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"[X] Gagal memproses FimLog: {e}"))