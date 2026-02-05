# ⚠ DISCLAIMER:
# This configuration is intended for portfolio and showcase purposes only.
# It does NOT represent the actual production configuration used on the live server.
# Sensitive values and production-level security settings are managed separately.

from rest_framework.generics import ListAPIView, CreateAPIView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny, BasePermission
from rest_framework.pagination import PageNumberPagination
from django.db.models import Count, Q
from django.db.models.functions import TruncDate
from django.conf import settings 
from django.core.cache import cache
from django.contrib.auth import authenticate
from datetime import date, timedelta, datetime
import os
import jwt

from .models import FimLog
from .serializers import (
    FimLogSerializer,
    FimLogIngestSerializer
)

# --- CONFIG ---
HOME_DIR = os.getenv('FIM_HOME_DIR', '/home/user/app') # change as needed
JWT_SECRET = settings.SECRET_KEY 
INCRON_STATUS_FILE = os.getenv('INCRON_STATUS_PATH', '/app/incron_status.txt') # change as needed

# --- PAGINATION ---
class StandardResultsSetPagination(PageNumberPagination):
    page_size = 10
    page_size_query_param = 'page_size'
    max_page_size = 1000

# --- CUSTOM PERMISSION ---
class IsAuthenticatedByJWT(BasePermission):
    """
    Custom Permission untuk memvalidasi JWT dari Cookie atau Header Authorization.
    Mendukung skenario di mana frontend (Next.js) mengirim token via HttpOnly Cookie
    atau via Header Authorization (Bearer Token).
    """
    def has_permission(self, request, view):
        token = None

        token = request.COOKIES.get('token')

        if not token:
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            if auth_header and auth_header.startswith('Bearer '):
                try:
                    token = auth_header.split(' ', 1)[1]
                except IndexError:
                    return False

        if not token:
            return False

        try:
            jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            return True
        except jwt.ExpiredSignatureError:
            return False
        except jwt.InvalidTokenError:
            return False
        except Exception:
            return False

# ==========================================
# AUTH & UTILS
# ==========================================

class CheckAuthView(APIView):
    """
    Endpoint sederhana untuk mengecek validitas token user saat ini.
    """
    permission_classes = [IsAuthenticatedByJWT] 
    
    def get(self, request):
        return Response({"message": "Authenticated"}, status=status.HTTP_200_OK)

class LoginApiView(APIView):
    """
    Menangani proses login, membuat JWT Token, dan menyimpannya dalam HttpOnly Cookie.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")
        
        user = authenticate(username=username, password=password)
        
        if user is not None:
            expiration = datetime.utcnow() + timedelta(hours=10)
            payload = { "user": user.username, "exp": expiration }
            token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
            
            response = Response({
                "message": "Login success",
                "token": token 
            })

            response.set_cookie(
                key="token",
                value=token,
                httponly=True,
                secure=True,
                samesite="None", 
                expires=expiration
            )
            return response
        else:
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

class LogoutView(APIView):
    """
    Menghapus sesi login dengan mengosongkan cookie token.
    """
    permission_classes = [AllowAny] 

    def post(self, request):
        response = Response({"message": "Logged out"})
        response.set_cookie(key="token", value="", httponly=True, expires='Thu, 01 Jan 1970 00:00:00 GMT')
        return response

class IncronControlApiView(APIView):
    """
    Checking the status of the Incron service (File System Watcher) via file status.
    """
    permission_classes = [IsAuthenticatedByJWT]
    
    def get(self, request, *args, **kwargs):
        is_running = False  
        try:
            with open(INCRON_STATUS_FILE, 'r') as f:
                if f.read().strip() == "running":
                    is_running = True
            return Response({"is_running": is_running})
        except FileNotFoundError:
            return Response({"is_running": False, "error": "Status file not found"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"is_running": False, "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# ==========================================
# INGEST & LOGS MANAGEMENT
# ==========================================

class IngestFimLogView(CreateAPIView):
    """
    Endpoint untuk Agent Python mengirimkan log perubahan file (Ingest).
    """
    permission_classes = [AllowAny] 
    queryset = FimLog.objects.all()
    serializer_class = FimLogIngestSerializer 

class LogApiView(ListAPIView):
    """
    Mengambil daftar log dengan fitur filtering, searching, dan pagination.
    """
    permission_classes = [IsAuthenticatedByJWT]
    serializer_class = FimLogSerializer
    pagination_class = StandardResultsSetPagination

    def get_queryset(self):
        queryset = FimLog.objects.all().order_by('-timestamp') 
        
        status_filter = self.request.query_params.get('status', None)
        if status_filter:
            status_filter = status_filter.lower()
            if status_filter == 'malware':
                queryset = queryset.filter(severity__icontains='MALWARE')
            elif status_filter == 'bahaya':
                queryset = queryset.filter(severity__icontains='BAHAYA')
            elif status_filter == 'mencurigakan':
                queryset = queryset.filter(severity__icontains='MENCURIGAKAN')
            elif status_filter == 'normal':
                queryset = queryset.exclude(severity__icontains='BAHAYA')\
                                   .exclude(severity__icontains='MENCURIGAKAN')\
                                   .exclude(severity__icontains='MALWARE')

        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(
                Q(path__icontains=search) | 
                Q(action__icontains=search) |
                Q(user__icontains=search) |
                Q(process__icontains=search)
            )
        return queryset

    def delete(self, request, *args, **kwargs):
        """
        Menghapus log berdasarkan ID (Bulk Delete atau Single Delete).
        """
        ids = request.data.get('ids', [])
        single_id = request.data.get('id')
        if single_id: ids.append(single_id)
        
        if not ids:
            return Response({"error": "No IDs provided"}, status=400)

        deleted_count, _ = FimLog.objects.filter(id__in=ids).delete()
        return Response({"message": f"{deleted_count} logs deleted"}, status=200)

# ==========================================
# ANALYTICS & DASHBOARD DATA
# ==========================================

class FimAnalyticsApiView(APIView):
    """
    Menyediakan statistik ringkas untuk hari ini (Total log per kategori severity).
    """
    permission_classes = [IsAuthenticatedByJWT]
    def get(self, request):
        today = date.today()
        stats = FimLog.objects.filter(timestamp__date=today).aggregate(
            total=Count('id'),
            malware=Count('id', filter=Q(severity__icontains='MALWARE')),
            bahaya=Count('id', filter=Q(severity__icontains='BAHAYA')),
            mencurigakan=Count('id', filter=Q(severity__icontains='MENCURIGAKAN'))
        )
        total = stats['total']
        malware = stats['malware']
        bahaya = stats['bahaya']
        mencurigakan = stats['mencurigakan']
        normal = total - (malware + bahaya + mencurigakan)
        
        return Response({
            "tanggal_analisis": today.strftime('%Y-%m-%d'),
            "total_perubahan_hari_ini": total,
            "detail": {
                "malware": malware, 
                "bahaya": bahaya, 
                "mencurigakan": mencurigakan, 
                "normal": normal
            }
        })

class FimHistoricalAnalyticsApiView(APIView):
    """
    Menyediakan data historis (default 7 hari terakhir) untuk visualisasi Chart.
    Menggunakan caching untuk mengurangi beban database pada query agregasi berat.
    """
    permission_classes = [IsAuthenticatedByJWT]
    def get(self, request):
        try: num_days = int(request.query_params.get('days', '7'))
        except: num_days = 7
        
        today = date.today()
        cache_key = f"fim_historical_chart_{today}_{num_days}"
        cached_data = cache.get(cache_key)
        if cached_data: return Response(cached_data)
        start_date = today - timedelta(days=num_days - 1)
        
        logs_stats = FimLog.objects.filter(timestamp__date__gte=start_date)\
            .annotate(date=TruncDate('timestamp'))\
            .values('date')\
            .annotate(
                total=Count('id'),
                malware=Count('id', filter=Q(severity__icontains='MALWARE')),
                bahaya=Count('id', filter=Q(severity__icontains='BAHAYA')),
                mencurigakan=Count('id', filter=Q(severity__icontains='MENCURIGAKAN'))
            ).order_by('date')
        
        stats_dict = {item['date'].strftime('%Y-%m-%d'): item for item in logs_stats if item['date']}
        
        response_list = []
        for i in range(num_days):
            target_date = today - timedelta(days=(num_days - 1) - i) 
            date_str = target_date.strftime('%Y-%m-%d')
            data = stats_dict.get(date_str, {'total': 0, 'malware': 0, 'bahaya': 0, 'mencurigakan': 0})
            
            normal = data['total'] - (data['malware'] + data['bahaya'] + data['mencurigakan'])
            response_list.append({
                "tanggal": date_str,
                "total_perubahan": data['total'],
                "detail": {
                    "malware": data['malware'],
                    "bahaya": data['bahaya'], 
                    "mencurigakan": data['mencurigakan'], 
                    "normal": normal
                }
            })
            
        cache.set(cache_key, response_list, 600) 
        return Response(response_list)

class FimTodayLogsApiView(APIView):
    """
    Retrieves specific log details for the current day, grouped by severity category.
    """
    permission_classes = [IsAuthenticatedByJWT]
    def get(self, request):
        today = date.today()
        logs = FimLog.objects.filter(timestamp__date=today).values(
            'id', 'timestamp', 'action', 'severity', 'path', 'user', 'process', 'full_log'
        ).order_by('-timestamp')
        
        data = {'malware': [], 'bahaya': [], 'mencurigakan': [], 'normal': []}
        
        for item in logs:
            path = item['path'] or ""
            process = item['process'] or ""
            severity = item['severity'] or ""
            
            comm = process.split("->")[0].strip() if "->" in process else process
            exe = process.split("->")[1].strip() if "->" in process else process

            formatted_item = {
                'id': item['id'],
                'tanggal': item['timestamp'].strftime('%Y-%m-%d'),
                'jam': item['timestamp'].strftime('%H:%M:%S'),
                'metode': item['action'],
                'nama_file': os.path.basename(path),
                'path_lengkap': path,
                'tag': severity,
                'user': item['user'],
                'comm': comm,
                'exe': exe,
                'full_log': item['full_log']
            }
            
            tag_lower = severity.lower()
            if 'malware' in tag_lower: data['malware'].append(formatted_item)
            elif 'bahaya' in tag_lower: data['bahaya'].append(formatted_item)
            elif 'mencurigakan' in tag_lower: data['mencurigakan'].append(formatted_item)
            else: data['normal'].append(formatted_item)
            
        return Response(data)

class FimLogsByDateApiView(APIView):
    """
    Same as FimTodayLogsApiView, but for a specific date selected by the user.
    """
    permission_classes = [IsAuthenticatedByJWT]
    def get(self, request):
        date_str = request.query_params.get('date')
        if not date_str: return Response({"error": "Date required"}, status=400)
        
        try: target_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError: return Response({"error": "Invalid date format"}, status=400)
        
        logs = FimLog.objects.filter(timestamp__date=target_date).values(
            'id', 'timestamp', 'action', 'severity', 'path', 'user', 'process', 'full_log'
        ).order_by('-timestamp')
        
        data = {'malware': [], 'bahaya': [], 'mencurigakan': [], 'normal': []}
        
        for item in logs:
            path = item['path'] or ""
            process = item['process'] or ""
            severity = item['severity'] or ""
            
            comm = process.split("->")[0].strip() if "->" in process else process
            exe = process.split("->")[1].strip() if "->" in process else process

            formatted_item = {
                'id': item['id'],
                'tanggal': item['timestamp'].strftime('%Y-%m-%d'),
                'jam': item['timestamp'].strftime('%H:%M:%S'),
                'metode': item['action'],
                'nama_file': os.path.basename(path),
                'path_lengkap': path,
                'tag': severity,
                'user': item['user'],
                'comm': comm,
                'exe': exe,
                'full_log': item['full_log']
            }
            tag_lower = severity.lower()
            if 'malware' in tag_lower: data['malware'].append(formatted_item)
            elif 'bahaya' in tag_lower: data['bahaya'].append(formatted_item)
            elif 'mencurigakan' in tag_lower: data['mencurigakan'].append(formatted_item)
            else: data['normal'].append(formatted_item)
            
        return Response(data)

class FimStatsByDateApiView(APIView):
    """
    Summary statistics for a specific date (used when the user clicks on a date in the calendar/chart).
    """
    permission_classes = [IsAuthenticatedByJWT]
    def get(self, request):
        date_str = request.query_params.get('date')
        if not date_str: return Response({"error": "Date required"}, status=400)
        
        try:
            target_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            return Response({"error": "Invalid date format"}, status=400)
        
        stats = FimLog.objects.filter(timestamp__date=target_date).aggregate(
            total=Count('id'),
            malware=Count('id', filter=Q(severity__icontains='MALWARE')),
            bahaya=Count('id', filter=Q(severity__icontains='BAHAYA')),
            mencurigakan=Count('id', filter=Q(severity__icontains='MENCURIGAKAN'))
        )
        total = stats['total']
        malware = stats['malware']
        bahaya = stats['bahaya']
        mencurigakan = stats['mencurigakan']
        
        return Response({
            "tanggal_analisis": date_str,
            "total_perubahan_hari_ini": total,
            "detail": {
                "malware": malware, 
                "bahaya": bahaya, 
                "mencurigakan": mencurigakan, 
                "normal": total - (malware + bahaya + mencurigakan)
            }
        })