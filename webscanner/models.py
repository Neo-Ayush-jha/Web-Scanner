from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone


class WebRole(models.TextChoices):
    ADMIN = 'Admin'
    ANALYST = 'Analyst'
    DEVELOPER = 'Developer'


class WebUser(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    role = models.CharField(max_length=20, choices=WebRole.choices, default=WebRole.ANALYST)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.user.username


class Target(models.Model):
    name = models.CharField(max_length=200)
    url = models.CharField(max_length=500)
    owner = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.name


class Scan(models.Model):
    SCAN_TYPES = (
        ('Passive', 'Passive'),
        ('Quick', 'Quick'),
        ('Full', 'Full'),
        ('SQLi', 'SQL Injection'),
        ('XSS', 'Cross Site Scripting'),
        ('Headers', 'Headers'),
    )

    target = models.ForeignKey(Target, on_delete=models.CASCADE)
    scan_type = models.CharField(max_length=30, choices=SCAN_TYPES, default='Passive')
    status = models.CharField(max_length=30, default='queued')
    progress = models.IntegerField(default=0)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    log = models.TextField(blank=True)

    def __str__(self):
        return f"Scan {self.id} - {self.status}"


class Vulnerability(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    vtype = models.CharField(max_length=200)
    severity = models.CharField(max_length=20)
    url = models.CharField(max_length=300, blank=True)
    parameter = models.CharField(max_length=100, blank=True)
    status = models.CharField(max_length=50, default='Open')
    evidence = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    created_at = models.DateTimeField(default=timezone.now)

    def __str__(self):
        return self.vtype
