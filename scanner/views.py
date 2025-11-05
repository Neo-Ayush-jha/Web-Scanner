from celery import shared_task
from django.utils import timezone
from .models import ScanTask, ScanResult
import subprocess
import xml.etree.ElementTree as ET
import os
import sys
import socket
from urllib.parse import urlparse

from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
import uuid
import json


# --------------------- Celery Task ---------------------
@shared_task(bind=True)
def run_scan(self, scan_id):
    try:
        scan = ScanTask.objects.get(pk=scan_id)
    except ScanTask.DoesNotExist:
        return {'error': 'scan not found'}

    scan.status = 'RUNNING'
    scan.start_time = timezone.now()
    scan.save()

    target = scan.target
    ports = scan.port_range

    # Full path to Nmap (Windows)
    nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
    if not os.path.exists(nmap_path):
        scan.status = 'FAILED'
        scan.end_time = timezone.now()
        scan.save()
        return {'error': f'nmap not found at {nmap_path}'}

    scan_type = '-sT'
    if sys.platform.startswith('win'):
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin:
                scan_type = '-sS'
        except Exception:
            pass

    try:
        xml_out = subprocess.check_output(
            [nmap_path, scan_type, '-Pn', '-p', ports, '-oX', '-', target],
            text=True,
            stderr=subprocess.STDOUT
        )
    except subprocess.CalledProcessError as e:
        scan.status = 'FAILED'
        scan.end_time = timezone.now()
        scan.save()
        return {'error': 'nmap scan failed', 'details': e.output}
    except Exception as e:
        scan.status = 'FAILED'
        scan.end_time = timezone.now()
        scan.save()
        return {'error': 'unexpected error', 'details': str(e)}

    try:
        root = ET.fromstring(xml_out)
        for host in root.findall('host'):
            for ports_el in host.findall('ports'):
                for port_el in ports_el.findall('port'):
                    portid = int(port_el.get('portid'))
                    state_el = port_el.find('state')
                    state = state_el.get('state') if state_el is not None else 'unknown'
                    reason = state_el.get('reason') if state_el is not None else ''
                    ttl = state_el.get('reason_ttl') if state_el is not None else ''
                    service_el = port_el.find('service')
                    service = service_el.get('name') if service_el is not None else ''

                    if state in ['open', 'filtered', 'closed']:
                        ScanResult.objects.create(
                            scan=scan,
                            port=portid,
                            state=state,
                            service=service,
                            reason=reason,
                            ttl=ttl
                        )
    except ET.ParseError as e:
        scan.status = 'FAILED'
        scan.end_time = timezone.now()
        scan.save()
        return {'error': 'failed to parse nmap XML', 'details': str(e)}

    scan.status = 'COMPLETED'
    scan.end_time = timezone.now()
    scan.save()
    return {'status': 'completed', 'scan_id': scan_id}


# --------------------- Utility ---------------------
def _extract_hostname_from_target(target_str: str) -> str | None:
    """
    Accepts a full URL, hostname or IP-like string and returns:
      - hostname (if URL or domain provided)
      - the original string if it's already an IP
    Returns None if nothing valid found.
    """
    if not target_str:
        return None

    # Trim spaces
    s = target_str.strip()

    # If it already looks like an IP, return as-is
    # (simple IPv4 check)
    parts = s.split('.')
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return s

    # Try parse as URL
    if '://' in s or s.startswith('www.'):
        try:
            parsed = urlparse(s if '://' in s else f'http://{s}')
            hostname = parsed.hostname
            return hostname
        except Exception:
            return None

    # Otherwise assume it's a bare domain (example.com)
    return s


def _resolve_ipv4(hostname: str) -> str | None:
    """
    Resolves hostname to an IPv4 address. Returns first IPv4 string or None.
    """
    try:
        # getaddrinfo returns tuples, filter for AF_INET (IPv4)
        addrs = socket.getaddrinfo(hostname, None)
        for entry in addrs:
            family, _socktype, _proto, _canonname, sockaddr = entry
            if family == socket.AF_INET:
                return sockaddr[0]
    except Exception:
        pass
    return None


# --------------------- Django Views ---------------------
def index(request):
    return render(request, 'scanner/index.html')


@csrf_exempt
def start_scan(request):
    """
    POST JSON:
      { "target": "<ip|domain|url>", "ports":"1-1024" }
    If target is a URL/domain, this view will resolve it to an IPv4 and scan the IP.
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)

    data = json.loads(request.body.decode('utf-8'))
    raw_target = data.get('target')
    ports = data.get('ports', '1-1024')

    if not raw_target:
        return JsonResponse({'error': 'target required'}, status=400)

    hostname = _extract_hostname_from_target(raw_target)
    if not hostname:
        return JsonResponse({'error': 'could not parse target'}, status=400)

    # If hostname is already IPv4, keep; else resolve
    if hostname.count('.') == 3 and all(p.isdigit() for p in hostname.split('.')):
        ip_to_scan = hostname
    else:
        ip_to_scan = _resolve_ipv4(hostname)
        if not ip_to_scan:
            return JsonResponse({'error': f'could not resolve {hostname}'}, status=400)

    unique_task = str(uuid.uuid4())
    # save the resolved IP as scan.target so the task runs against IP
    scan = ScanTask.objects.create(
        task_id=unique_task,
        target=ip_to_scan,
        port_range=ports,
        status='PENDING',
    )
    async_result = run_scan.delay(scan.id)

    return JsonResponse({
        'scan_db_id': scan.id,
        'task_uuid': unique_task,
        'celery_id': async_result.id,
        'resolved_ip': ip_to_scan
    })


def scan_status(request, scan_id):
    scan = get_object_or_404(ScanTask, pk=scan_id)
    results = list(scan.scanresult_set.values('port', 'state', 'service'))
    return JsonResponse({
        'scan_db_id': scan.id,
        'target': scan.target,
        'status': scan.status,
        'results': results,
        'start_time': scan.start_time,
        'end_time': scan.end_time
    })


def export_csv(request, scan_id):
    scan = get_object_or_404(ScanTask, pk=scan_id)
    results = scan.scanresult_set.all().order_by('port')
    lines = ['port,state,service']
    for r in results:
        lines.append(f"{r.port},{r.state},{r.service or ''}")
    resp = HttpResponse('\n'.join(lines), content_type='text/csv')
    resp['Content-Disposition'] = f'attachment; filename="scan_{scan_id}.csv"'
    return resp


# --------------------- New Resolve Endpoint (robust for URLs) ---------------------
@csrf_exempt
def resolve_domain(request):
    """
    POST JSON:
      {"domain": "<domain-or-full-url-or-ip>"}
    Returns resolved IPv4 address (first IPv4).
    """
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)

    data = json.loads(request.body.decode('utf-8'))
    target = data.get('domain') or data.get('target')
    if not target:
        return JsonResponse({'error': 'domain required'}, status=400)

    hostname = _extract_hostname_from_target(target)
    if not hostname:
        return JsonResponse({'error': 'could not parse domain/URL'}, status=400)

    # If hostname already is IPv4, return it
    if hostname.count('.') == 3 and all(p.isdigit() for p in hostname.split('.')):
        return JsonResponse({'domain': target, 'ip_address': hostname})

    ip = _resolve_ipv4(hostname)
    if not ip:
        return JsonResponse({'error': f'could not resolve {hostname}'}, status=400)

    return JsonResponse({'domain': target, 'hostname': hostname, 'ip_address': ip})


def home(request):
    return render(request, 'scanner/home.html')
