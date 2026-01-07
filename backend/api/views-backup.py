from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import BasePermission, AllowAny, IsAuthenticated
import os
import json
from datetime import datetime, timedelta
import hashlib
import subprocess
import re
import jwt
from django.conf import settings
from datetime import date, timedelta
from collections import Counter


#  Config
HOME_DIR = "/home/webadm1"
TRASH_LOG_FILE = os.path.join(HOME_DIR, "fim_trash_log.txt")
JWT_SECRET = settings.SECRET_KEY 
WP_ACTIVITY_LOG_FILE = os.path.join(HOME_DIR, "activitywordpress_log.txt")
VALID_USERNAME = os.environ.get("APP_USERNAME") 
VALID_PASSWORD = os.environ.get("APP_PASSWORD") 

class IsAuthenticatedByJWT(BasePermission):
    def has_permission(self, request, view):
        token = request.COOKIES.get('token')
        if not token:
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ', 1)[1]

        if not token:
            return False

        try:
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            return True
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return False


class CheckAuthView(APIView):
    permission_classes = [IsAuthenticatedByJWT]

    def get(self, request):
        return Response({"message": "Authenticated"}, status=status.HTTP_200_OK)

def parse_log_lines(lines):

    parsed_logs = []
    
    log_pattern = re.compile(
        r'^\[(.*?)\]\s+'         
        r'(\[.*?\]\s+.*?|.*?):'   
        r'\s+(.*?)'               
        r'(?:\s+(oleh .*))?$'     
    )

    pelaku_pattern = re.compile(r'oleh\s(.*?)\s\(via\s(.*?)(?:\s->\s(.*?))?\)')
    
    for line in lines: 
        line = line.strip()
        if not line: continue
        
        log_id = hashlib.md5(line.encode()).hexdigest()
        
        match = log_pattern.match(line)
        if not match:
            continue 

        try:
            timestamp_str = match.group(1)
            metode_dan_tag = match.group(2).strip()
            path_lengkap = match.group(3).strip()   
            info_pelaku_raw = match.group(4)     

            dt_obj = datetime.strptime(timestamp_str, '%d-%m-%Y %H:%M:%S')
            tanggal = dt_obj.strftime('%Y-%m-%d')
            jam = dt_obj.strftime('%H:%M:%S')
            
            nama_file = os.path.basename(path_lengkap)
            
            tag = ""
            metode = metode_dan_tag
            if metode_dan_tag.startswith('['):
                tag_end = metode_dan_tag.find('] ')
                if tag_end != -1:
                    tag = metode_dan_tag[:tag_end + 1]
                    metode = metode_dan_tag[tag_end + 2:]

            user = None
            comm = None
            exe = None
            
            if info_pelaku_raw:
                pelaku_match = pelaku_pattern.search(info_pelaku_raw)
                if pelaku_match:
                    user = pelaku_match.group(1)
                    comm = pelaku_match.group(2)
                    exe = pelaku_match.group(3)

            parsed_logs.append({
                "id": log_id,
                "tanggal": tanggal,
                "jam": jam,
                "metode": metode.strip(),
                "nama_file": nama_file,
                "path_lengkap": path_lengkap,
                "tag": tag.strip(),
                "user": user,   
                "comm": comm,   
                "exe": exe      
            })
        except (IndexError, ValueError, AttributeError):
            continue
            
    return parsed_logs

def parse_wp_log_lines(lines):
    parsed_logs = []
    for line in lines:
        line = line.strip()
        if not line: continue
        
        try:
            log_data = json.loads(line)
            log_id = hashlib.md5(line.encode()).hexdigest()
            log_data['id'] = log_id
            parsed_logs.append(log_data)
        except json.JSONDecodeError:
            continue
    return parsed_logs

class LoginApiView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        if username != VALID_USERNAME or password != VALID_PASSWORD:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
        
        expiration = datetime.utcnow() + timedelta(hours=10)

        payload = {
            "user": username,
            "exp": expiration 
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

        response = Response({"message": "Login success"})
        response.set_cookie(
            key="token",
            value=token,
            httponly=True,
            secure=True, 
            samesite="None",
            expires=expiration 
        )
        return response

class LogoutView(APIView):
    def post(self, request):
        response = Response({"message": "Logged out"})
        
        response.set_cookie(
            key="token",
            value="",  
            httponly=True,
            secure=True,
            samesite="None",  
            expires='Thu, 01 Jan 1970 00:00:00 GMT'
        )
        return response

class LogApiView(APIView):
    permission_classes = [IsAuthenticatedByJWT]
    def get_log_file_path(self):
        activity_log = os.path.join(HOME_DIR, "fim_activity_log.txt")
        default_log = os.path.join(HOME_DIR, "fim_log.txt")
        
        if os.path.exists(activity_log):
            return activity_log
        elif os.path.exists(default_log):
            return default_log
        return None

    def get(self, request, *args, **kwargs):
        log_to_read = self.get_log_file_path()
        if not log_to_read:
            return Response({"error": "Log file not found"}, status=status.HTTP_404_NOT_FOUND)
        
        try:
            with open(log_to_read, 'r') as f:
                lines = f.readlines()[::-1]
            all_logs = parse_log_lines(lines)

            status_filter = request.query_params.get('status', None)
            logs_to_process = []
            if status_filter:
                status_filter = status_filter.lower()
                for log in all_logs:
                    tag = log.get('tag', '').lower()
                    if status_filter == 'bahaya' and '[bahaya]' in tag:
                        logs_to_process.append(log)
                    elif status_filter == 'mencurigakan' and '[kegiatan mencurigakan]' in tag:
                        logs_to_process.append(log)
                    elif status_filter == 'normal' and '[bahaya]' not in tag and '[kegiatan mencurigakan]' not in tag:
                        logs_to_process.append(log)
            else:
                logs_to_process = all_logs

            search_query = request.query_params.get('search', None)
            if search_query:
                search_query = search_query.lower()
                filtered_logs = []
                for log in logs_to_process:
                    nama_file = str(log.get('nama_file', '')).lower()
                    path_lengkap = str(log.get('path_lengkap', '')).lower()
                    tag = str(log.get('tag', '')).lower()
                    tanggal = str(log.get('tanggal', '')) 
                    jam = str(log.get('jam', ''))         
                    user = str(log.get('user') or '').lower() 
                    comm = str(log.get('comm') or '').lower() 
                    
                    if (search_query in nama_file or
                        search_query in path_lengkap or
                        search_query in tag or
                        search_query in tanggal or
                        search_query in jam or
                        search_query in user or
                        search_query in comm):
                        filtered_logs.append(log)
            else:
                filtered_logs = logs_to_process

            # Pagination
            page_number = int(request.query_params.get('page', 1))
            items_per_page = 10 
            
            total_items = len(filtered_logs)
            total_pages = (total_items + items_per_page - 1) // items_per_page
            start_index = (page_number - 1) * items_per_page
            end_index = start_index + items_per_page
            
            paginated_logs = filtered_logs[start_index:end_index]

            response_data = {
                'count': total_items, 'total_pages': total_pages,
                'current_page': page_number, 'results': paginated_logs,
            }
            return Response(response_data)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    def delete(self, request, *args, **kwargs):
        log_ids_to_move = request.data.get('ids', []) 
        single_log_id = request.data.get('id')
        
        if single_log_id and not log_ids_to_move:
            log_ids_to_move.append(single_log_id)

        if not log_ids_to_move:
            return Response({"error": "Log ID or IDs are required"}, status=status.HTTP_400_BAD_REQUEST)

        log_file = self.get_log_file_path()
        if not log_file:
            return Response({"error": "Log file not found"}, status=status.HTTP_404_NOT_FOUND)

        try:
            with open(log_file, 'r') as f:
                lines = f.readlines()
            
            ids_set = set(log_ids_to_move) 
            new_lines = []
            lines_to_move = []
            
            for line in lines:
                line_stripped = line.strip()
                if not line_stripped:
                    new_lines.append(line)
                    continue
                
                current_log_id = hashlib.md5(line_stripped.encode()).hexdigest()
                if current_log_id in ids_set:
                    lines_to_move.append(line)
                else:
                    new_lines.append(line)

            if not lines_to_move:
                return Response({"error": "No matching Log IDs found"}, status=status.HTTP_404_NOT_FOUND)

            with open(log_file, 'w') as f:
                f.writelines(new_lines)
            
            with open(TRASH_LOG_FILE, 'a') as f:
                f.writelines(lines_to_move)

            return Response({"message": f"{len(lines_to_move)} log entries moved to trash"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class WpActivityLogApiView(APIView):
    permission_classes = [IsAuthenticatedByJWT]

    def get(self, request, *args, **kwargs):
        if not os.path.exists(WP_ACTIVITY_LOG_FILE):
            return Response({'count': 0, 'total_pages': 0, 'current_page': 1, 'results': []})

        try:
            with open(WP_ACTIVITY_LOG_FILE, 'r', encoding='utf-8') as f:
                lines = f.readlines()[::-1] 
            all_logs = parse_wp_log_lines(lines)
            
            # --- Filtering ---
            category_filter = request.query_params.get('category', None)
            user_filter = request.query_params.get('user', None)
            ip_filter = request.query_params.get('ip', None)
            search_query = request.query_params.get('search', None)

            logs_to_process = all_logs

            if category_filter:
                logs_to_process = [log for log in logs_to_process if log.get('category', '').lower() == category_filter.lower()]
            if user_filter:
                logs_to_process = [log for log in logs_to_process if log.get('user', '').lower() == user_filter.lower()]
            if ip_filter:
                logs_to_process = [log for log in logs_to_process if log.get('ip', '') == ip_filter]
            
            if search_query:
                search_query = search_query.lower()
                logs_to_process = [log for log in logs_to_process if
                                   search_query in str(log.get('action', '')).lower() or
                                   search_query in str(log.get('details', '')).lower() or
                                   search_query in str(log.get('user', '')).lower() or
                                   search_query in str(log.get('ip', '')).lower()]

            # --- Pagination ---
            page_number = int(request.query_params.get('page', 1))
            items_per_page = 10
            total_items = len(logs_to_process)
            total_pages = (total_items + items_per_page - 1) // items_per_page
            start_index = (page_number - 1) * items_per_page
            end_index = start_index + items_per_page
            paginated_logs = logs_to_process[start_index:end_index]

            response_data = {
                'count': total_items, 'total_pages': total_pages,
                'current_page': page_number, 'results': paginated_logs,
            }
            return Response(response_data)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class WpAnalyticsApiView(APIView):
    permission_classes = [IsAuthenticatedByJWT]

    def get(self, request, *args, **kwargs):
        if not os.path.exists(WP_ACTIVITY_LOG_FILE):
            return Response({"error": "File log aktivitas WordPress tidak ditemukan."}, status=status.HTTP_404_NOT_FOUND)

        try:
            try:
                num_days_trend = int(request.query_params.get('days', '30'))
                if num_days_trend not in [7, 15, 30]:
                     num_days_trend = 30
            except ValueError:
                num_days_trend = 30

            today = date.today()
            trend_start_date = today - timedelta(days=num_days_trend - 1)
            thirty_days_ago = today - timedelta(days=30)
            summary_today = { 'login_success': 0, 'login_fail': 0, 'content_activity': 0, 'plugin_activity': 0 }
            user_activity = Counter()
            ip_activity = Counter()
            failed_login_ips = Counter()

            trend_data = {
                (today - timedelta(days=i)).strftime('%Y-%m-%d'): {
                    'login_success': 0, 'login_fail': 0, 'content': 0, 'plugin': 0
                } for i in range(num_days_trend) 
            }

            all_logs = []
            with open(WP_ACTIVITY_LOG_FILE, 'r', encoding='utf-8') as f:
                 for line in f:
                     try:
                         all_logs.append(json.loads(line))
                     except json.JSONDecodeError:
                         continue

            for log in all_logs:
                try:
                    log_date = datetime.strptime(log.get("timestamp", ""), '%Y-%m-%d %H:%M:%S').date()
                    category = log.get("category", "Unknown").lower()
                    action = log.get("action", "Unknown").lower()

                    if log_date == today:
                        if category == "login" and action == "success": summary_today['login_success'] += 1
                        elif category == "login" and action == "failed": summary_today['login_fail'] += 1
                        elif category == "content": summary_today['content_activity'] += 1
                        elif category == "plugin": summary_today['plugin_activity'] += 1

                    if log_date >= thirty_days_ago:
                        user_activity[log.get("user", "N/A")] += 1
                        ip_activity[log.get("ip", "N/A")] += 1     
                        if category == "login" and action == "failed":
                             failed_login_ips[log.get("ip", "N/A")] += 1 

                    if log_date >= trend_start_date: 
                        log_date_str = log_date.strftime('%Y-%m-%d')
                        if log_date_str in trend_data:
                            if category == "login" and action == "success": trend_data[log_date_str]['login_success'] += 1
                            elif category == "login" and action == "failed": trend_data[log_date_str]['login_fail'] += 1
                            elif category == "content": trend_data[log_date_str]['content'] += 1
                            elif category == "plugin": trend_data[log_date_str]['plugin'] += 1
                except (ValueError, TypeError):
                    continue 

            trend_list = [{'date': d, **counts} for d, counts in sorted(trend_data.items())]
            response_data = {
                "summary_today": summary_today,
                "top_5_users": user_activity.most_common(5),
                "top_5_ips": ip_activity.most_common(5),
                "top_5_failed_ips": failed_login_ips.most_common(5),
                "trend_analysis": trend_list,
            }
            return Response(response_data)

        except Exception as e:
            import traceback
            print(traceback.format_exc()) 
            return Response({"error": f"Kesalahan internal server: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class WpTodayLogsApiView(APIView):
    permission_classes = [IsAuthenticatedByJWT]

    def get(self, request, *args, **kwargs):
        if not os.path.exists(WP_ACTIVITY_LOG_FILE):
            return Response({"error": "File log aktivitas WordPress tidak ditemukan."}, status=status.HTTP_404_NOT_FOUND)

        try:
            today = date.today()
            
            response_data = {
                'login': [],
                'plugin': [],
                'content': [],
                'user_management': [],
                'lainnya': [] 
            }

            with open(WP_ACTIVITY_LOG_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line)
                        
                        log_date = datetime.strptime(log_entry.get("timestamp", ""), '%Y-%m-%d %H:%M:%S').date()

                        if log_date == today:
                            category = log_entry.get("category", "Unknown").lower()
                            
                            if category == 'login':
                                response_data['login'].append(log_entry)
                            elif category == 'plugin':
                                response_data['plugin'].append(log_entry)
                            elif category == 'content':
                                response_data['content'].append(log_entry)
                            elif category == 'user management':
                                response_data['user_management'].append(log_entry)
                            else:
                                response_data['lainnya'].append(log_entry)

                    except (json.JSONDecodeError, ValueError, TypeError):
                        continue
            
            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class WpStatsByDateApiView(APIView):
    permission_classes = [IsAuthenticatedByJWT]

    def get(self, request, *args, **kwargs):
        target_date_str = request.query_params.get('date', None)
        if not target_date_str:
            return Response({"error": "Parameter 'date' diperlukan."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            target_date = datetime.strptime(target_date_str, '%Y-%m-%d').date()
        except ValueError:
            return Response({"error": "Format tanggal tidak valid. Gunakan YYYY-MM-DD."}, status=status.HTTP_400_BAD_REQUEST)

        if not os.path.exists(WP_ACTIVITY_LOG_FILE):
            return Response({"error": "File log aktivitas WordPress tidak ditemukan."}, status=status.HTTP_404_NOT_FOUND)

        try:
            summary = { 'login_success': 0, 'login_fail': 0, 'content_activity': 0, 'plugin_activity': 0 }
            
            with open(WP_ACTIVITY_LOG_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line)
                        log_date = datetime.strptime(log_entry.get("timestamp", ""), '%Y-%m-%d %H:%M:%S').date()
                        
                        if log_date == target_date:
                            category = log_entry.get("category", "Unknown").lower()
                            action = log_entry.get("action", "Unknown").lower()
                            if category == "login" and action == "success":
                                summary['login_success'] += 1
                            elif category == "login" and action == "failed":
                                summary['login_fail'] += 1
                            elif category == "content":
                                summary['content_activity'] += 1
                            elif category == "plugin":
                                summary['plugin_activity'] += 1
                    except (json.JSONDecodeError, ValueError, TypeError):
                        continue
            
            response_data = {
                "tanggal_analisis": target_date_str,
                "total_perubahan_hari_ini": sum(summary.values()), 
                "detail": summary 
            }
            return Response(response_data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class WpLogsByDateApiView(APIView):
    permission_classes = [IsAuthenticatedByJWT]

    def get(self, request, *args, **kwargs):
        target_date_str = request.query_params.get('date', None)
        if not target_date_str:
            return Response({"error": "Parameter 'date' diperlukan."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            target_date = datetime.strptime(target_date_str, '%Y-%m-%d').date()
        except ValueError:
            return Response({"error": "Format tanggal tidak valid. Gunakan YYYY-MM-DD."}, status=status.HTTP_400_BAD_REQUEST)

        if not os.path.exists(WP_ACTIVITY_LOG_FILE):
            return Response({"error": "File log aktivitas WordPress tidak ditemukan."}, status=status.HTTP_404_NOT_FOUND)

        try:
            response_data = { 'login': [], 'plugin': [], 'content': [], 'user_management': [], 'lainnya': [] }
            
            with open(WP_ACTIVITY_LOG_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    try:
                        log_entry = json.loads(line)
                        log_date = datetime.strptime(log_entry.get("timestamp", ""), '%Y-%m-%d %H:%M:%S').date()
                        
                        if log_date == target_date:
                            category = log_entry.get("category", "Unknown").lower()
                            if category == 'login': response_data['login'].append(log_entry)
                            elif category == 'plugin': response_data['plugin'].append(log_entry)
                            elif category == 'content': response_data['content'].append(log_entry)
                            elif category == 'user management': response_data['user_management'].append(log_entry)
                            else: response_data['lainnya'].append(log_entry)
                    except (json.JSONDecodeError, ValueError, TypeError):
                        continue
            
            return Response(response_data, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class TrashApiView(APIView):
    permission_classes = [IsAuthenticatedByJWT]
    def get(self, request, *args, **kwargs):
        if not os.path.exists(TRASH_LOG_FILE):
            return Response({'count': 0, 'total_pages': 0, 'current_page': 1, 'results': []})
        
        try:
            with open(TRASH_LOG_FILE, 'r') as f:
                lines = f.readlines()[::-1]
            all_logs = parse_log_lines(lines)

            # Filter Status 
            status_filter = request.query_params.get('status', None)
            logs_to_process = []
            if status_filter:
                status_filter = status_filter.lower()
                for log in all_logs:
                    tag = log.get('tag', '').lower()
                    if status_filter == 'bahaya' and '[bahaya]' in tag:
                        logs_to_process.append(log)
                    elif status_filter == 'mencurigakan' and '[kegiatan mencurigakan]' in tag:
                        logs_to_process.append(log)
                    elif status_filter == 'normal' and '[bahaya]' not in tag and '[kegiatan mencurigakan]' not in tag:
                        logs_to_process.append(log)
            else:
                logs_to_process = all_logs

            # Search 
            search_query = request.query_params.get('search', None)
            if search_query:
                search_query = search_query.lower()
                filtered_logs = [
                    log for log in logs_to_process 
                    if search_query in log['nama_file'].lower() or \
                       search_query in log['path_lengkap'].lower() or \
                       search_query in log['tag'].lower() or \
                       search_query in log['tanggal'] or \
                       search_query in log['jam'] 
                ]
            else:
                filtered_logs = logs_to_process

            # Pagination 
            page_number = int(request.query_params.get('page', 1))
            items_per_page = 10
            
            total_items = len(filtered_logs)
            total_pages = (total_items + items_per_page - 1) // items_per_page
            start_index = (page_number - 1) * items_per_page
            end_index = start_index + items_per_page
            paginated_logs = filtered_logs[start_index:end_index]
            
            response_data = {
                'count': total_items, 'total_pages': total_pages,
                'current_page': page_number, 'results': paginated_logs,
            }
            return Response(response_data)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


    def post(self, request, log_id=None, *args, **kwargs):
        if not log_id:
            return Response({"error": "Log ID is required in the URL"}, status=status.HTTP_400_BAD_REQUEST)

        main_log_file = LogApiView().get_log_file_path()
        if not main_log_file:
            return Response({"error": "Main log file not found, cannot restore"}, status=status.HTTP_404_NOT_FOUND)

        try:
            with open(TRASH_LOG_FILE, 'r') as f:
                trash_lines = f.readlines()
            
            new_trash_lines = []
            line_to_restore = None
            found = False
            for line in trash_lines:
                line_stripped = line.strip()
                if not line_stripped:
                    new_trash_lines.append(line)
                    continue
                
                if hashlib.md5(line_stripped.encode()).hexdigest() == log_id:
                    found = True
                    line_to_restore = line
                else:
                    new_trash_lines.append(line)
            
            if not found:
                return Response({"error": "Log ID not found in trash"}, status=status.HTTP_404_NOT_FOUND)
            
            with open(TRASH_LOG_FILE, 'w') as f:
                f.writelines(new_trash_lines)
            
            with open(main_log_file, 'a') as f:
                f.write(line_to_restore)
            
            return Response({"message": "Log entry restored successfully"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self, request, log_id=None, *args, **kwargs):
        log_ids_to_delete = request.data.get('ids', []) 
        
        if log_id and not log_ids_to_delete: 
             log_ids_to_delete.append(log_id)

        try:
            if not os.path.exists(TRASH_LOG_FILE):
                return Response({"message": "Trash is already empty"}, status=status.HTTP_200_OK)

            if log_ids_to_delete:
                with open(TRASH_LOG_FILE, 'r') as f:
                    lines = f.readlines()
                
                ids_set = set(log_ids_to_delete)
                new_lines = []
                found_count = 0
                
                for line in lines:
                    line_stripped = line.strip()
                    if not line_stripped:
                        new_lines.append(line)
                        continue
                    
                    if hashlib.md5(line_stripped.encode()).hexdigest() in ids_set:
                        found_count += 1
                    else:
                        new_lines.append(line)

                if found_count == 0:
                    return Response({"error": "No matching Log IDs found in trash"}, status=status.HTTP_404_NOT_FOUND)
                
                with open(TRASH_LOG_FILE, 'w') as f:
                    f.writelines(new_lines)
                
                return Response({"message": f"{found_count} log entries permanently deleted"}, status=status.HTTP_200_OK)
            
            else:
                os.remove(TRASH_LOG_FILE)
                return Response({"message": "Trash has been emptied"}, status=status.HTTP_200_OK)
                
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class IncronControlApiView(APIView):
    permission_classes = [IsAuthenticatedByJWT]
    def get(self, request, *args, **kwargs):
        status_file_path = "/app/incron_status.txt"
        is_running = False  

        try:
            with open(status_file_path, 'r') as f:
                status_dari_file = f.read().strip()
            
            if status_dari_file == "running":
                is_running = True
            
            return Response({"is_running": is_running})

        except FileNotFoundError:
          
            return Response({
                "is_running": False, 
                "error": "File status incron tidak ditemukan. Periksa konfigurasi volume di docker-compose.yml."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        except Exception as e:
            return Response({
                "is_running": False, 
                "error": f"Terjadi kesalahan umum: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class FimAnalyticsApiView(APIView):
    permission_classes = [IsAuthenticatedByJWT]

    def get(self, request, *args, **kwargs):
        log_api_view = LogApiView()
        log_file_path = log_api_view.get_log_file_path()

        if not log_file_path or not os.path.exists(log_file_path):
            return Response({"error": "Log file not found"}, status=status.HTTP_404_NOT_FOUND)

        try:
            today_str = date.today().strftime('%Y-%m-%d')
            
            total_perubahan_hari_ini = 0
            perubahan_bahaya = 0
            perubahan_mencurigakan = 0
            perubahan_normal = 0

            with open(log_file_path, 'r') as f:
                for line in f:
                    parsed_log_list = parse_log_lines([line]) 
                    if not parsed_log_list:
                        continue
                    
                    log_entry = parsed_log_list[0]

                    if log_entry.get('tanggal') == today_str:
                        total_perubahan_hari_ini += 1
                        tag = log_entry.get('tag', '').lower()
                        
                        if '[bahaya]' in tag:
                            perubahan_bahaya += 1
                        elif '[kegiatan mencurigakan]' in tag:
                            perubahan_mencurigakan += 1
                        else:
                            perubahan_normal += 1
            
            response_data = {
                "tanggal_analisis": today_str,
                "total_perubahan_hari_ini": total_perubahan_hari_ini,
                "detail": {
                    "bahaya": perubahan_bahaya,
                    "mencurigakan": perubahan_mencurigakan,
                    "normal": perubahan_normal
                }
            }
            
            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class FimHistoricalAnalyticsApiView(APIView):
    permission_classes = [IsAuthenticatedByJWT]

    def get(self, request, *args, **kwargs):
        try:
            num_days = int(request.query_params.get('days', '7'))
            if num_days <= 0 or num_days > 90: 
                return Response(
                    {"error": "Parameter 'days' harus antara 1 dan 90."},
                    status=status.HTTP_400_BAD_REQUEST
                )
        except ValueError:
            return Response(
                {"error": "Parameter 'days' harus berupa angka."}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        analytics_data = {}
        today = date.today()
        for i in range(num_days):
            target_date = today - timedelta(days=i)
            target_date_str = target_date.strftime('%Y-%m-%d')
            analytics_data[target_date_str] = {
                'total': 0, 'bahaya': 0, 'mencurigakan': 0, 'normal': 0
            }
        
        log_api_view = LogApiView()
        log_file_path = log_api_view.get_log_file_path()

        if not log_file_path or not os.path.exists(log_file_path):
            return Response({"error": "Log file not found"}, status=status.HTTP_404_NOT_FOUND)

        try:
            with open(log_file_path, 'r') as f:
                for line in f:
                    parsed_log_list = parse_log_lines([line])
                    if not parsed_log_list:
                        continue
                    
                    log_entry = parsed_log_list[0]
                    log_date = log_entry.get('tanggal')

                    if log_date in analytics_data:
                        analytics_data[log_date]['total'] += 1
                        tag = log_entry.get('tag', '').lower()
                        
                        if '[bahaya]' in tag:
                            analytics_data[log_date]['bahaya'] += 1
                        elif '[kegiatan mencurigakan]' in tag:
                            analytics_data[log_date]['mencurigakan'] += 1
                        else:
                            analytics_data[log_date]['normal'] += 1
            
            response_list = []
            for date_str, counts in sorted(analytics_data.items(), reverse=True):
                response_list.append({
                    "tanggal": date_str,
                    "total_perubahan": counts['total'],
                    "detail": {
                        "bahaya": counts['bahaya'],
                        "mencurigakan": counts['mencurigakan'],
                        "normal": counts['normal']
                    }
                })

            return Response(response_list, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class FimTodayLogsApiView(APIView):
    permission_classes = [IsAuthenticatedByJWT]

    def get(self, request, *args, **kwargs):
        log_api_view = LogApiView()
        log_file_path = log_api_view.get_log_file_path()

        if not log_file_path or not os.path.exists(log_file_path):
            return Response({"error": "Log file not found"}, status=status.HTTP_404_NOT_FOUND)

        try:
            today_str = date.today().strftime('%Y-%m-%d')
            
            response_data = {
                'bahaya': [],
                'mencurigakan': [],
                'normal': []
            }

            with open(log_file_path, 'r') as f:
                for line in f:
                    parsed_log_list = parse_log_lines([line])
                    if not parsed_log_list:
                        continue
                    
                    log_entry = parsed_log_list[0]

                    if log_entry.get('tanggal') == today_str:
                        tag = log_entry.get('tag', '').lower()
                        
                        if '[bahaya]' in tag:
                            response_data['bahaya'].append(log_entry)
                        elif '[kegiatan mencurigakan]' in tag:
                            response_data['mencurigakan'].append(log_entry)
                        else:
                            response_data['normal'].append(log_entry)
            
            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class FimLogsByDateApiView(APIView):
    permission_classes = [IsAuthenticatedByJWT]

    def get(self, request, *args, **kwargs):
        target_date_str = request.query_params.get('date', None)

        if not target_date_str:
            return Response(
                {"error": "Parameter 'date' diperlukan."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            datetime.strptime(target_date_str, '%Y-%m-%d')
        except ValueError:
            return Response(
                {"error": "Format tanggal tidak valid. Gunakan format YYYY-MM-DD."},
                status=status.HTTP_400_BAD_REQUEST
            )

        log_api_view = LogApiView()
        log_file_path = log_api_view.get_log_file_path()

        if not log_file_path or not os.path.exists(log_file_path):
            return Response({"error": "Log file not found"}, status=status.HTTP_404_NOT_FOUND)

        try:
            response_data = {
                'bahaya': [],
                'mencurigakan': [],
                'normal': []
            }

            with open(log_file_path, 'r') as f:
                for line in f:
                    parsed_log_list = parse_log_lines([line])
                    if not parsed_log_list:
                        continue
                    
                    log_entry = parsed_log_list[0]

                    if log_entry.get('tanggal') == target_date_str:
                        tag = log_entry.get('tag', '').lower()
                        
                        if '[bahaya]' in tag:
                            response_data['bahaya'].append(log_entry)
                        elif '[kegiatan mencurigakan]' in tag:
                            response_data['mencurigakan'].append(log_entry)
                        else:
                            response_data['normal'].append(log_entry)
            
            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class FimStatsByDateApiView(APIView):
    permission_classes = [IsAuthenticatedByJWT]

    def get(self, request, *args, **kwargs):
        target_date_str = request.query_params.get('date', None)

        if not target_date_str:
            return Response({"error": "Parameter 'date' diperlukan."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            datetime.strptime(target_date_str, '%Y-%m-%d')
        except ValueError:
            return Response({"error": "Format tanggal tidak valid. Gunakan YYYY-MM-DD."}, status=status.HTTP_400_BAD_REQUEST)

        log_api_view = LogApiView()
        log_file_path = log_api_view.get_log_file_path()

        if not log_file_path or not os.path.exists(log_file_path):
            return Response({"error": "Log file not found"}, status=status.HTTP_404_NOT_FOUND)

        try:
            total_changes = 0
            danger_changes = 0
            suspicious_changes = 0
            normal_changes = 0

            with open(log_file_path, 'r') as f:
                for line in f:
                    parsed_log_list = parse_log_lines([line])
                    if not parsed_log_list:
                        continue
                    
                    log_entry = parsed_log_list[0]

                    if log_entry.get('tanggal') == target_date_str:
                        total_changes += 1
                        tag = log_entry.get('tag', '').lower()
                        
                        if '[bahaya]' in tag:
                            danger_changes += 1
                        elif '[kegiatan mencurigakan]' in tag:
                            suspicious_changes += 1
                        else:
                            normal_changes += 1
            
            response_data = {
                "tanggal_analisis": target_date_str,
                "total_perubahan_hari_ini": total_changes,
                "detail": {
                    "bahaya": danger_changes,
                    "mencurigakan": suspicious_changes,
                    "normal": normal_changes
                }
            }
            
            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)