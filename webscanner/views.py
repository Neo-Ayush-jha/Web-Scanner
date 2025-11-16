from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import Target, Scan, Vulnerability
from .tasks import run_web_scan

@login_required
def webscanner_dashboard(request):
    # stats
    total_scans = Scan.objects.count()
    total_vulns = Vulnerability.objects.count()

    severity = {
        "Critical": Vulnerability.objects.filter(severity="Critical").count(),
        "High": Vulnerability.objects.filter(severity="High").count(),
        "Medium": Vulnerability.objects.filter(severity="Medium").count(),
        "Low": Vulnerability.objects.filter(severity="Low").count(),
    }

    # Overall risk score calculation done in Python
    overall_risk = (
        severity["Critical"] * 5 +
        severity["High"] * 3 +
        severity["Medium"] * 2 +
        severity["Low"]
    )

    latest_scans = Scan.objects.order_by('-id')[:10]

    # Most vulnerable targets
    most_vulnerable = [
        (t, Vulnerability.objects.filter(scan__target=t).count())
        for t in Target.objects.all()
    ]
    most_vulnerable = sorted(most_vulnerable, key=lambda x: x[1], reverse=True)[:5]

    context = {
        "stats": {
            "total_scans": total_scans,
            "total_vulns": total_vulns,
            "severity": severity
        },
        "overall_risk": overall_risk,
        "latest_scans": latest_scans,
        "most_vulnerable": most_vulnerable,
    }

    return render(request, 'webscanner/dashboard.html', context)


@login_required
def add_target(request):
    if request.method == 'POST':
        name = request.POST['name']
        url = request.POST['url']
        Target.objects.create(name=name, url=url, owner=request.user)
        return redirect('web_targets')

    targets = Target.objects.all()
    return render(request, 'webscanner/targets.html', {'targets': targets})


@login_required
def start_web_scan(request, target_id):
    target = Target.objects.get(id=target_id)
    scan = Scan.objects.create(target=target, scan_type='Full')
    run_web_scan.delay(scan.id)
    return redirect('web_scans')


@login_required
def web_scans(request):
    scans = Scan.objects.order_by('-id')
    return render(request, 'webscanner/scans.html', {'scans': scans})


@login_required
def scan_status(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    return JsonResponse({
        'status': scan.status,
        'progress': scan.progress,
        'log': scan.log,
    })


@login_required
def web_results(request):
    vulns = Vulnerability.objects.order_by('-created_at')[:500]

    severity_list = ["Critical", "High", "Medium", "Low"]

    return render(request, 'webscanner/results.html', {
        'vulns': vulns,
        'severity_list': severity_list,
    })


@login_required
def scan_log(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    return JsonResponse({"log": scan.log})

@login_required
def delete_target(request, t_id):
    target = get_object_or_404(Target, id=t_id)
    target.delete()
    return redirect('web_targets')


from django.http import FileResponse
from .reports import generate_pdf_report, generate_html_report, generate_csv_report

@login_required
def report_view(request, scan_id):
    fmt = request.GET.get("format", "pdf")

    if fmt == "pdf":
        file_path = generate_pdf_report(scan_id)
    elif fmt == "html":
        file_path = generate_html_report(scan_id)
    elif fmt == "csv":
        file_path = generate_csv_report(scan_id)
    else:
        return JsonResponse({"error": "Unknown report format"}, status=400)

    return FileResponse(open(file_path, "rb"), as_attachment=True)


@login_required
def scan_cancel(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    scan.status = "cancelled"
    scan.save()
    return redirect('web_scans')
