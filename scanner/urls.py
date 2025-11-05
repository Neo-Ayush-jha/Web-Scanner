from django.urls import path
from . import views

urlpatterns = [
     path('', views.home, name='home'),             
    path('scanner/', views.index, name='scanner'),
    # path('', views.index, name='index'),
    path('api/start_scan/', views.start_scan, name='start_scan'),
    path('api/status/<int:scan_id>/', views.scan_status, name='scan_status'),
    path('api/export/<int:scan_id>/', views.export_csv, name='export_csv'),
    # auth
    path('register/', views.register_user, name='register'),
    path('login/', views.login_user, name='login'),
    path('logout/', views.logout_user, name='logout'),
    # payment
    path('payment/', views.make_payment, name='make_payment'),
    path('verify-payment/', views.verify_payment, name='verify_payment'),
]
