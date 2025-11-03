from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .models import ScanTask, ScanResult
from .tasks import run_scan
import uuid
import json
from .port_info import PORT_DETAILS


def index(request):
    return render(request, 'scanner/index.html')

@csrf_exempt
def start_scan(request):
    if request.method != 'POST':
        return JsonResponse({'error':'POST only'}, status=405)
    data = json.loads(request.body.decode('utf-8'))
    target = data.get('target')
    ports = data.get('ports','1-1024')

    if not target:
        return JsonResponse({'error':'target required'}, status=400)

    unique_task = str(uuid.uuid4())
    scan = ScanTask.objects.create(task_id=unique_task, target=target, port_range=ports, status='PENDING')
    async_result = run_scan.delay(scan.id)
    return JsonResponse({'scan_db_id': scan.id, 'task_uuid': unique_task, 'celery_id': async_result.id})

def scan_status(request, scan_id):
    scan = get_object_or_404(ScanTask, pk=scan_id)
    results = list(scan.scanresult_set.values('port', 'state', 'service'))

    for r in results:
        r['description'] = PORT_DETAILS.get(r['port'], "No description available for this port.")

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

    lines = ['port,state,service,description']
    for r in results:
        description = PORT_DETAILS.get(r.port, "No description available for this port.")
        lines.append(f"{r.port},{r.state},{r.service or ''},{description}")

    resp = HttpResponse('\n'.join(lines), content_type='text/csv')
    resp['Content-Disposition'] = f'attachment; filename="scan_{scan_id}.csv"'
    return resp

def home(request):
    return render(request, 'scanner/home.html')
