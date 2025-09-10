from django.contrib import admin
from .models import ScanTask, ScanResult

class ScanResultInline(admin.TabularInline):
    model = ScanResult
    extra = 0

@admin.register(ScanTask)
class ScanTaskAdmin(admin.ModelAdmin):
    list_display = ('id','task_id','target','status','start_time','end_time')
    inlines = [ScanResultInline]
    search_fields = ('task_id','target','status')
    list_filter = ('status','start_time','end_time')
    readonly_fields = ('created_at',)
    ordering = ('-created_at',)
    