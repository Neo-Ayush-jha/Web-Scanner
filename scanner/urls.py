from django.urls import path
from . import views

app_name = 'scanner'
urlpatterns = [
    path('', views.home, name='home'),             
    path('scanner/', views.index, name='scanner'),
    # path('', views.index, name='index'),
    path('api/start_scan/', views.start_scan, name='start_scan'),
    path('api/status/<int:scan_id>/', views.scan_status, name='scan_status'),
    path('api/export/<int:scan_id>/', views.export_csv, name='export_csv'),
]
