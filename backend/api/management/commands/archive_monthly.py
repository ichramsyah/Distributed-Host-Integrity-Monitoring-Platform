from django.core.management.base import BaseCommand
from api.models import FimLog
from django.conf import settings  
import csv
import os
from datetime import date, timedelta

class Command(BaseCommand):
    help = 'Backup data bulan lalu ke CSV dan hapus dari database'

    def handle(self, *args, **kwargs):
        today = date.today()
        first_day_this_month = today.replace(day=1)
        last_day_prev_month = first_day_this_month - timedelta(days=1)
        first_day_prev_month = last_day_prev_month.replace(day=1)
        month_str = first_day_prev_month.strftime('%Y-%m')
        
        BACKUP_DIR = os.path.join(settings.BASE_DIR, 'backup_logs')
        
        if not os.path.exists(BACKUP_DIR):
            os.makedirs(BACKUP_DIR)

        self.stdout.write(f"Memproses data periode: {first_day_prev_month} s.d {last_day_prev_month}")

        self.backup_fim(
            filename=f"{BACKUP_DIR}/fim_log_{month_str}.csv",
            start_date=first_day_prev_month,
            end_date=last_day_prev_month
        )

    def backup_fim(self, filename, start_date, end_date):
        logs = FimLog.objects.filter(timestamp__date__gte=start_date, timestamp__date__lte=end_date)
        count = logs.count()

        if count == 0:
            self.stdout.write(self.style.WARNING(f"Tidak ada data FimLog untuk periode ini."))
            return

        self.stdout.write(f"Menemukan {count} data FimLog. Menulis ke CSV...")

        try:
            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile, delimiter=';')
                
                headers = ['Tanggal', 'Jam', 'User', 'Nama File', 'Action', 'Command', 'Lokasi', 'Path Lengkap']
                writer.writerow(headers)

                for log in logs.iterator():
                    nama_file = os.path.basename(log.path) if log.path else "-"
                    
                    cmd_val = getattr(log, 'command', '-') 
                    cwd_val = getattr(log, 'process', '-') 

                    row = [
                        log.timestamp.strftime('%Y-%m-%d'), 
                        log.timestamp.strftime('%H:%M'),    
                        log.user or "unknown",
                        nama_file,
                        log.action,
                        cmd_val,  
                        cwd_val,  
                        log.path
                    ]
                    writer.writerow(row)
            
            self.stdout.write(self.style.SUCCESS(f"Sukses backup FIM ke {filename}"))

            deleted, _ = logs.delete()
            self.stdout.write(self.style.SUCCESS(f"Berhasil menghapus {deleted} data FimLog dari database."))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Gagal memproses FimLog: {e}"))