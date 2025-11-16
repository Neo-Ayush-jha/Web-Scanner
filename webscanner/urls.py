from django.urls import path
from . import views

urlpatterns = [
    path('', views.webscanner_dashboard, name='web_dashboard'),
    path('targets/', views.add_target, name='web_targets'),
    path('scan/<int:target_id>/', views.start_web_scan, name='web_start_scan'),
    path('scans/', views.web_scans, name='web_scans'),
    path('scan_status/<int:scan_id>/', views.scan_status, name='web_scan_status'),
    path('results/', views.web_results, name='web_results'),
    path('scan_log/<int:scan_id>/', views.scan_log, name='scan_log'),
    path('targets/delete/<int:t_id>/', views.delete_target, name='delete_target'),
    path('report/<int:scan_id>/', views.report_view, name='report'),
    path('scan_cancel/<int:scan_id>/', views.scan_cancel, name='scan_cancel'),
    
]