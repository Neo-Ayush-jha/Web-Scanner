from celery import shared_task
from django.utils import timezone
from .models import ScanTask, ScanResult
import subprocess
import xml.etree.ElementTree as ET
import os
import sys
import socket
from urllib.parse import urlparse

def extract_hostname(target: str) -> str:
    """
    Extract pure hostname from input like:
    https://owasp.org/www-project-juice-shop/  -> owasp.org
    owasp.org:8080 -> owasp.org
    104.20.44.163 -> 104.20.44.163
    """
    parsed = urlparse(target)
    if parsed.scheme and parsed.netloc:
        host = parsed.netloc
    else:
        host = parsed.path or target
    # remove port and credentials if present
    if '@' in host:
        host = host.split('@')[-1]
    if ':' in host:
        host = host.split(':')[0]
    return host.strip()

def resolve_ip(hostname: str) -> str:
    """
    Resolve hostname to IP (IPv4 preferred).
    """
    try:
        # first try IPv4
        infos = socket.getaddrinfo(hostname, None)
        for info in infos:
            family, _, _, _, sockaddr = info
            if family == socket.AF_INET:
                return sockaddr[0]
        # fallback: return first found address
        if infos:
            return infos[0][4][0]
    except Exception:
        return hostname  # fallback if resolution fails
    return hostname


@shared_task(bind=True)
def run_scan(self, scan_id):
    import socket
    from urllib.parse import urlparse
    from django.utils import timezone
    from .models import ScanTask, ScanResult
    import subprocess, xml.etree.ElementTree as ET, os, sys, requests

    def extract_hostname(target: str) -> str:
        parsed = urlparse(target)
        if parsed.scheme and parsed.netloc:
            host = parsed.netloc
        else:
            host = parsed.path or target
        if '@' in host:
            host = host.split('@')[-1]
        if ':' in host:
            host = host.split(':')[0]
        return host.strip()

    def resolve_all_ipv4(hostname: str):
        try:
            infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
            return list(set([info[4][0] for info in infos]))
        except Exception:
            return []

    # STEP 1: Fetch scan info
    try:
        scan = ScanTask.objects.get(pk=scan_id)
    except ScanTask.DoesNotExist:
        return {'error': 'scan not found'}

    scan.status = 'RUNNING'
    scan.start_time = timezone.now()
    scan.save()

    hostname = extract_hostname(scan.target)
    ipv4_list = resolve_all_ipv4(hostname)
    ports = scan.port_range

    if not ipv4_list and not hostname.replace('.', '').isdigit():
        scan.status = 'FAILED'
        scan.end_time = timezone.now()
        scan.save()
        return {'error': f'Could not resolve {hostname}'}

    targets = ipv4_list if ipv4_list else [hostname]

    # STEP 2: Find Nmap path
    possible_paths = [
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe",
        "/usr/bin/nmap",
        "/bin/nmap",
        "nmap"
    ]
    nmap_path = next((p for p in possible_paths if p == "nmap" or os.path.exists(p)), None)
    if not nmap_path:
        scan.status = 'FAILED'
        scan.end_time = timezone.now()
        scan.save()
        return {'error': 'nmap not found'}

    scan_type = '-sT'
    if sys.platform.startswith('win'):
        try:
            import ctypes
            if ctypes.windll.shell32.IsUserAnAdmin() != 0:
                scan_type = '-sS'
        except Exception:
            pass

    open_ports = []
    for ip in targets:
        try:
            # Force IPv4 (-4) and include filtered ports
            xml_out = subprocess.check_output(
                [nmap_path, '-4', scan_type, '-Pn', '-p', ports, '-oX', '-', ip],
                text=True, stderr=subprocess.STDOUT
            )
        except Exception:
            continue

        try:
            root = ET.fromstring(xml_out)
            for host in root.findall('host'):
                for ports_el in host.findall('ports'):
                    for port_el in ports_el.findall('port'):
                        portid = int(port_el.get('portid'))
                        state_el = port_el.find('state')
                        state = state_el.get('state') if state_el is not None else 'unknown'
                        service_el = port_el.find('service')
                        service = service_el.get('name') if service_el is not None else ''

                        # ✅ Treat 'filtered' as open (for Cloudflare)
                        if state in ['open', 'filtered']:
                            ScanResult.objects.create(
                                scan=scan,
                                port=portid,
                                state=state,
                                service=service or ''
                            )
                            open_ports.append((ip, portid, state, service))
        except ET.ParseError:
            continue

    # ✅ STEP 3: Fallback HTTP check (for domains behind CDN)
    try:
        r = requests.get(f"http://{hostname}", timeout=5)
        if r.status_code < 500:
            ScanResult.objects.get_or_create(
                scan=scan,
                port=80,
                defaults={'state': 'open', 'service': 'http'}
            )
            open_ports.append((hostname, 80, 'open', 'http'))
    except Exception:
        pass

    try:
        r = requests.get(f"https://{hostname}", timeout=5)
        if r.status_code < 500:
            ScanResult.objects.get_or_create(
                scan=scan,
                port=443,
                defaults={'state': 'open', 'service': 'https'}
            )
            open_ports.append((hostname, 443, 'open', 'https'))
    except Exception:
        pass

    # STEP 4: Finalize
    scan.status = 'COMPLETED'
    scan.end_time = timezone.now()
    scan.save()

    return {
        'status': 'completed',
        'hostname': hostname,
        'scanned_ips': targets,
        'open_ports': open_ports
    }
