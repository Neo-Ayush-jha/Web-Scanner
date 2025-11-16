from django.shortcuts import render, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from .models import *
from .tasks import run_scan
import uuid
import json
from .port_info import PORT_DETAILS
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
import razorpay


def index(request):
    return render(request, 'scanner/index.html')

@csrf_exempt
@login_required
def start_scan(request):
    if request.method != 'POST':
        return JsonResponse({'error':'POST only'}, status=405)
    data = json.loads(request.body.decode('utf-8'))
    target = data.get('target')
    ports = data.get('ports','1-1024')

    if not target:
        return JsonResponse({'error':'target required'}, status=400)

    profile, _ = UserProfile.objects.get_or_create(user=request.user)

    # If user not paid and has used 3 scans => require payment
    if (not profile.has_paid) and profile.scan_count >= 3:
        return JsonResponse({'error':'Free scan limit reached. Payment required to continue.', 'payment_required': True}, status=403)

    unique_task = str(uuid.uuid4())
    scan = ScanTask.objects.create(task_id=unique_task, target=target, port_range=ports, status='PENDING')
    async_result = run_scan.delay(scan.id)

    # increment only when we successfully queued scan
    profile.scan_count += 1
    profile.save()

    return JsonResponse({'scan_db_id': scan.id, 'task_uuid': unique_task, 'celery_id': async_result.id})

def scan_status(request, scan_id):
    scan = get_object_or_404(ScanTask, pk=scan_id)
    results = list(scan.scanresult_set.values('port', 'state', 'service'))

    for r in results:
        port_info = PORT_DETAILS.get(r['port'], None)
        if port_info:
            r['name'] = port_info['name']
            r['description'] = port_info['description']
            r['risk_level'] = port_info['risk_level']
            r['usage'] = port_info['usage']
        else:
            r['name'] = "Unknown Port"
            r['description'] = "No detailed information found for this port."
            r['risk_level'] = "Unknown"
            r['usage'] = "N/A"

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

    lines = ['port,name,state,service,risk_level,description,usage']
    for r in results:
        port_info = PORT_DETAILS.get(r.port, None)
        if port_info:
            lines.append(f"{r.port},{port_info['name']},{r.state},{r.service or ''},{port_info['risk_level']},{port_info['description']},{port_info['usage']}")
        else:
            lines.append(f"{r.port},Unknown,{r.state},{r.service or ''},Unknown,No description,N/A")

    resp = HttpResponse('\n'.join(lines), content_type='text/csv')
    resp['Content-Disposition'] = f'attachment; filename=\"scan_{scan_id}.csv\"'
    return resp

def home(request):
    return render(request, 'scanner/home.html')



from django.contrib.auth.models import User
from django.contrib import messages
from django.shortcuts import render, redirect

def register_user(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")

        if not username or not password:
            messages.error(request, "Username and password required.")
            return redirect('register')

        # ✅ Check username in User model (not UserProfile)
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
            return redirect('register')

        # ✅ Create user using User model (not UserProfile)
        user = User.objects.create_user(username=username, email=email, password=password)
        user.save()

        messages.success(request, "Registration successful. Please login.")
        return redirect('login')

    return render(request, 'scanner/register.html')



def login_user(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect('home')
        else:
            messages.error(request, "Invalid credentials.")
            return redirect('login')
    return render(request, 'scanner/login.html')

def logout_user(request):
    logout(request)
    return redirect('home')


@login_required
def make_payment(request):
    """Create Razorpay order and render payment page."""
    client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_SECRET))
    amount_rupees = 49  # set amount here
    amount_paise = int(amount_rupees * 100)
    razor_order = client.order.create({'amount': amount_paise, 'currency': 'INR', 'payment_capture': 1})
    payment = PaymentRecord.objects.create(user=request.user, razorpay_order_id=razor_order['id'], amount=amount_rupees)
    context = {
        'order': razor_order,
        'key_id': settings.RAZORPAY_KEY_ID,
        'amount': amount_paise,
    }
    return render(request, 'scanner/make_payment.html', context)


@csrf_exempt
def verify_payment(request):
    """Verify signature returned by Razorpay (called from frontend)."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    try:
        data = json.loads(request.body.decode('utf-8'))
        razorpay_order_id = data.get('razorpay_order_id')
        razorpay_payment_id = data.get('razorpay_payment_id')
        razorpay_signature = data.get('razorpay_signature')

        client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_SECRET))
        params = {
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_signature': razorpay_signature
        }
        try:
            client.utility.verify_payment_signature(params)
        except razorpay.errors.SignatureVerificationError:
            # signature invalid
            return JsonResponse({'status': 'failed', 'reason': 'signature_invalid'}, status=400)

        payment = PaymentRecord.objects.filter(razorpay_order_id=razorpay_order_id).first()
        if not payment:
            return JsonResponse({'status': 'failed', 'reason': 'order_not_found'}, status=404)

        payment.razorpay_payment_id = razorpay_payment_id
        payment.razorpay_signature = razorpay_signature
        payment.status = 'SUCCESS'
        payment.save()

        # mark user as paid and reset count
        profile = UserProfile.objects.get(user=payment.user)
        profile.has_paid = True
        profile.scan_count = 0
        profile.save()

        return JsonResponse({'status': 'success'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'error': str(e)}, status=500)
