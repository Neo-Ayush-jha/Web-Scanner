from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .models import ScanTask, ScanResult
from .tasks import run_scan
import uuid
import json

def index(request):
    return render(request, 'scanner/index.html')

@csrf_exempt
def start_scan(request):
    if request.method != 'POST':
        return JsonResponse({'error':'POST only'}, status=405)
    data = json.loads(request.body.decode('utf-8'))
    target = data.get('target')
    ports = data.get('ports','1-1024')

    # basic validation (improve for IPv6/regex)
    if not target:
        return JsonResponse({'error':'target required'}, status=400)

    # create a ScanTask record
    unique_task = str(uuid.uuid4())
    scan = ScanTask.objects.create(task_id=unique_task, target=target, port_range=ports, status='PENDING')
    # enqueue Celery task
    async_result = run_scan.delay(scan.id)
    # store the Celery task id (optional)
    # return the local scan.id and unique_task
    return JsonResponse({'scan_db_id': scan.id, 'task_uuid': unique_task, 'celery_id': async_result.id})

def scan_status(request, scan_id):
    scan = get_object_or_404(ScanTask, pk=scan_id)
    results = list(scan.scanresult_set.values('port','state','service'))
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

