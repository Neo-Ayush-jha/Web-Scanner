from celery import shared_task
from django.utils import timezone
from .models import ScanTask, ScanResult
import subprocess
import xml.etree.ElementTree as ET
import os
import sys

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

    # Optional: Use SYN scan if admin privileges (Windows requires Admin for -sS)
    scan_type = '-sT'  # default TCP connect
    if sys.platform.startswith('win'):
        # Check if admin rights (simplified check)
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin:
                scan_type = '-sS'
        except Exception:
            pass

    try:
        # Run Nmap with XML output
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

    # Parse XML output
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

                    # Optional: store only open/filtered/closed ports
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
