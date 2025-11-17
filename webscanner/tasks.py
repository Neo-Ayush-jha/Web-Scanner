from celery import shared_task
from django.utils import timezone
from django.db import transaction
from .models import Scan, Target, Vulnerability
import requests
from bs4 import BeautifulSoup
import time


def append_log(scan, msg):
    scan.log = (scan.log or "") + msg + "\n"
    scan.save(update_fields=["log"])
    

def fetch_target(scan, target):
    try:
        resp = requests.get(target.url, timeout=8)
        meta = f"HTTP {resp.status_code}, {len(resp.content)} bytes"
        append_log(scan, f"Fetched: {meta}")
    except Exception as e:
        append_log(scan, f"Fetch failed: {e}")


def check_headers(scan, target):
    try:
        resp = requests.get(target.url, timeout=8)
        headers = resp.headers
        missing = []

        required = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'Referrer-Policy'
        ]

        for h in required:
            if h not in headers:
                missing.append(h)

        if missing:
            Vulnerability.objects.create(
                scan=scan,
                vtype='Security Misconfiguration',
                severity='Medium',
                url=target.url,
                parameter='headers',
                evidence=f"Missing headers: {', '.join(missing)}",
                remediation='Add recommended security headers.'
            )
            append_log(scan, f"Missing headers: {', '.join(missing)}")

    except Exception as e:
        append_log(scan, f"Header check failed: {e}")


def simulate_sqli(scan, target):
    Vulnerability.objects.create(
        scan=scan,
        vtype='SQL Injection',
        severity='Medium',
        url=target.url,
        parameter='q',
        evidence="Simulated SQLi detection",
        remediation="Use parameterized queries."
    )
    append_log(scan, "Potential SQLi found")


def simulate_xss(scan, target):
    Vulnerability.objects.create(
        scan=scan,
        vtype='Cross-Site Scripting (XSS)',
        severity='Medium',
        url=target.url,
        parameter='term',
        evidence='Simulated XSS detection',
        remediation='Implement output encoding.'
    )
    append_log(scan, "Potential XSS found")


def check_misconfig(scan, target):
    try:
        resp = requests.get(target.url, timeout=8)
        if "X-Powered-By" in resp.headers:
            Vulnerability.objects.create(
                scan=scan,
                vtype='Information Disclosure',
                severity='Low',
                url=target.url,
                parameter='header',
                evidence=f"X-Powered-By: {resp.headers.get('X-Powered-By')}",
                remediation='Remove X-Powered-By header.'
            )
            append_log(scan, "Information Disclosure: X-Powered-By present")
    except:
        pass


def fingerprint_components(scan, target):
    try:
        resp = requests.get(target.url, timeout=8)
        soup = BeautifulSoup(resp.text, "html.parser")

        libs = []
        for s in soup.find_all("script"):
            src = s.get("src") or ""
            if "jquery" in src:
                libs.append("jQuery")
            if "bootstrap" in src:
                libs.append("Bootstrap")

        if libs:
            Vulnerability.objects.create(
                scan=scan,
                vtype="Outdated Components",
                severity="Low",
                url=target.url,
                parameter="script",
                evidence=f"Detected libs: {', '.join(set(libs))}",
                remediation="Update third-party libraries."
            )
            append_log(scan, f"Detected libs: {', '.join(set(libs))}")

    except:
        pass



@shared_task
def run_web_scan(scan_id):
    scan = Scan.objects.get(id=scan_id)
    target = scan.target

    scan.status = "running"
    scan.progress = 0
    scan.started_at = timezone.now()
    scan.save()

    append_log(scan, f"Starting scan on {target.url} ({scan.scan_type})")

    steps = [
        ("Fetching target", fetch_target),
        ("Checking headers", check_headers),
        ("Simulate SQLi probes", simulate_sqli),
        ("Simulate XSS probes", simulate_xss),
        ("Check misconfiguration", check_misconfig),
        ("Fingerprint components", fingerprint_components)
    ]

    per_step = 100 // len(steps)

    for idx, (msg, func) in enumerate(steps):
        append_log(scan, f"Step {idx+1}/{len(steps)}: {msg}")

        func(scan, target)

        scan.progress = (idx + 1) * per_step
        scan.save()

        time.sleep(0.3)

    scan.status = "completed"
    scan.finished_at = timezone.now()
    scan.progress = 100
    scan.save()

    append_log(scan, "Scan completed successfully")
    return True
