from django.db import models
from django.utils import timezone

class ScanTask(models.Model):
    STATUS_CHOICES = [
        ('PENDING','Pending'),
        ('RUNNING','Running'),
        ('COMPLETED','Completed'),
        ('FAILED','Failed'),
    ]
    task_id = models.CharField(max_length=255, unique=True)
    target = models.CharField(max_length=255)
    port_range = models.CharField(max_length=50, default='1-1024')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    start_time = models.DateTimeField(null=True, blank=True)
    end_time = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return f"{self.target} ({self.task_id}) - {self.status}"


class ScanResult(models.Model):
    scan = models.ForeignKey('ScanTask', on_delete=models.CASCADE)
    port = models.IntegerField()
    state = models.CharField(max_length=20)
    service = models.CharField(max_length=100, blank=True)
    reason = models.CharField(max_length=50, blank=True)  
    ttl = models.CharField(max_length=10, blank=True)  
    description = models.TextField(null=True, blank=True)    
    def __str__(self):
        return f"{self.scan.target}:{self.port} {self.state}"
