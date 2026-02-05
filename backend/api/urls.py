"""
📂 API URL CONFIGURATION
========================
Route definitions for the FIM (File Integrity Monitoring) System Backend.
Includes endpoints for Authentication, Data Ingestion (Agent), and Dashboard Analytics.
"""

from django.urls import path
from .views import (
    # Auth & Utils
    LoginApiView, LogoutView, CheckAuthView, IncronControlApiView,
    
    # Ingest 
    IngestFimLogView,
    
    # FIM Dashboard
    LogApiView, 
    FimAnalyticsApiView, FimHistoricalAnalyticsApiView, 
    FimTodayLogsApiView, FimLogsByDateApiView, FimStatsByDateApiView,
)

urlpatterns = [
    # --- Auth ---
    path('login/', LoginApiView.as_view(), name='api-login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('check-auth/', CheckAuthView.as_view(), name='check-auth'),
    
    # --- Ingest ---
    path('ingest/fim/', IngestFimLogView.as_view(), name='ingest_fim'),
    
    # --- FIM Dashboard ---
    path('logs/', LogApiView.as_view(), name='log-list'), 
    path('logs/analytics/', FimAnalyticsApiView.as_view(), name='fim_analytics'),
    path('logs/analytics/historical/', FimHistoricalAnalyticsApiView.as_view(), name='fim_hist'),
    path('logs/today/', FimTodayLogsApiView.as_view(), name='fim_today'),
    path('logs/by-date/', FimLogsByDateApiView.as_view(), name='fim_logs_by_date'),
    path('logs/stats-by-date/', FimStatsByDateApiView.as_view(), name='fim_stats_by_date'),
    
    # --- Incron Control ---
    path('incron/control/', IncronControlApiView.as_view(), name='incron-control'),
]