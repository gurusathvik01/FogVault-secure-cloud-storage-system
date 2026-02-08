from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from .models import AuditLog
from .models import SecureFile, AuditLog
from .models import SecureFile, AuditLog, UserSecurity
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from .utils import send_otp
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.shortcuts import render, redirect
from .models import OTP
from .utils import send_otp
from .models import OTP
from .utils import send_otp
from django.contrib.auth.hashers import make_password
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.models import User
from django.http import FileResponse



from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from .utils import send_otp
from django.http import FileResponse


from .models import OTP


def forgot_password(request):
    if request.method == "POST":
        email = request.POST["email"]
        if User.objects.filter(email=email).exists():
            send_otp(email)
            request.session["reset_email"] = email
            return redirect("reset_password")

    return render(request, "forgot-password.html")
from django.contrib.auth.hashers import make_password

def reset_password(request):
    if request.method == "POST":
        otp = request.POST["otp"]
        password = request.POST["password"]
        email = request.session["reset_email"]

        record = OTP.objects.filter(email=email, code=otp).first()

        if record and record.is_valid():
            user = User.objects.get(email=email)
            user.password = make_password(password)
            user.save()

            record.delete()
            return redirect("login")

        return render(request, "reset-password.html", {"error": "Invalid OTP"})

    return render(request, "reset-password.html")




def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            return redirect('upload')
        else:
            return render(request, 'login.html', {
                'error': 'Invalid credentials'
            })

    return render(request, 'login.html')
from django.contrib.auth import logout


def user_logout(request):
    logout(request)
    return redirect('login')
from django.contrib.auth.decorators import login_required
from .models import SecureFile


from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.views.decorators.csrf import csrf_protect
from django.utils import timezone

from .models import SecureFile


# ======================
# HOME
# ======================
def home(request):
    return render(request, 'home.html')


# ======================
# LOGIN
# ======================
@csrf_protect
def user_login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(request, username=username, password=password)

        if user:
            login(request, user)
            return redirect("/upload/")
        else:
            return render(request, "login.html", {
                "error": "Invalid username or password"
            })

    return render(request, "login.html")


# ======================
# UPLOAD
# ======================
@login_required
def upload_file(request):
    if request.method == 'POST':
        f = request.FILES.get('file')
        if f:
            SecureFile.objects.create(
                user=request.user,
                file=f
            )
            return redirect('upload')

    recent_files = SecureFile.objects.filter(
        user=request.user,
        is_deleted=False
    ).order_by('-uploaded_at')[:5]

    return render(request, 'upload.html', {
        'recent_files': recent_files
    })


# ======================
# FILES PAGE
# ======================
@login_required
def files_page(request):
    files = SecureFile.objects.filter(
        user=request.user,
        is_deleted=False
    ).order_by('-uploaded_at')

    return render(request, 'files.html', {
        'files': files
    })


# ======================
# HISTORY PAGE
# ======================
@login_required
def history_page(request):
    history = SecureFile.objects.filter(
        user=request.user
    ).order_by('-uploaded_at')

    return render(request, 'history.html', {
        'history': history
    })


# ======================
# TRASH PAGE
# ======================
@login_required
def trash_page(request):
    trash_files = SecureFile.objects.filter(
        user=request.user,
        is_deleted=True
    ).order_by('-deleted_at')

    return render(request, 'trash.html', {
        'trash_files': trash_files
    })


# ======================
# MOVE TO TRASH
# ======================
@login_required
def move_to_trash(request, file_id):
    f = get_object_or_404(SecureFile, id=file_id, user=request.user)

    f.is_deleted = True
    f.deleted_at = timezone.now()
    f.deleted_by = request.user   # 🔥 THIS LINE WAS MISSING
    f.save()

    AuditLog.objects.create(
        user=request.user,
        file=f,
        action="DELETE"
    )

    return redirect('files')



# ======================
# RESTORE FILE
# ======================
@login_required
def restore_file(request, file_id):
    f = get_object_or_404(
        SecureFile,
        id=file_id,
        user=request.user
    )
    f.is_deleted = False
    f.deleted_at = None
    f.save()

    return redirect('trash')


# ======================
# PERMANENT DELETE
# ======================
@login_required
def permanent_delete(request, file_id):
    f = get_object_or_404(
        SecureFile,
        id=file_id,
        user=request.user
    )
    f.file.delete(save=False)
    f.delete()

    return redirect('trash')
from django.http import JsonResponse

@login_required
def toggle_star(request, file_id):
    f = get_object_or_404(SecureFile, id=file_id, user=request.user)
    f.is_starred = not f.is_starred
    f.save()
    return JsonResponse({"starred": f.is_starred})
from django.contrib.auth.decorators import login_required

@login_required
def starred_page(request):
    files = SecureFile.objects.filter(
        user=request.user,
        is_starred=True,
        is_deleted=False
    ).order_by('-uploaded_at')

    return render(request, "starred.html", {
        "files": files
    })
from django.http import JsonResponse
from django.views.decorators.http import require_POST

@login_required
@require_POST
def toggle_star(request, file_id):
    file = get_object_or_404(SecureFile, id=file_id, user=request.user)

    file.is_starred = not file.is_starred
    file.save()

    return JsonResponse({
        "starred": file.is_starred
    })
@login_required
@require_POST
def bulk_delete(request):
    ids = request.POST.getlist("ids[]")
    SecureFile.objects.filter(
        id__in=ids,
        user=request.user
    ).update(is_deleted=True, deleted_at=timezone.now())
    return JsonResponse({"status": "ok"})
@login_required
@require_POST
def bulk_star(request):
    ids = request.POST.getlist("ids[]")
    SecureFile.objects.filter(
        id__in=ids,
        user=request.user
    ).update(is_starred=True)
    return JsonResponse({"status": "ok"})

from django.views.decorators.http import require_POST
from django.http import JsonResponse
from django.utils import timezone

@login_required
@require_POST
def bulk_restore(request):
    ids = request.POST.getlist("ids[]")
    SecureFile.objects.filter(
        id__in=ids,
        user=request.user
    ).update(is_deleted=False, deleted_at=None)
    return JsonResponse({"status": "ok"})



@login_required
@require_POST
def bulk_permanent_delete(request):
    ids = request.POST.getlist("ids[]")
    files = SecureFile.objects.filter(
        id__in=ids,
        user=request.user
    )

    for f in files:
        f.file.delete(save=False)
        f.delete()

    return JsonResponse({"status": "ok"})
@login_required
def open_file(request, file_id):
    f = get_object_or_404(SecureFile, id=file_id, user=request.user)

    AuditLog.objects.create(
        user=request.user,
        file=f,
        action="OPEN"
    )

    return redirect(f.file.url)
@login_required
def audit_page(request):
    logs = AuditLog.objects.filter(
        user=request.user
    ).select_related("file").order_by("-timestamp")

    return render(request, "audit.html", {"logs": logs})
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from django.utils import timezone

from .models import SecureFile, AuditLog


@login_required
def upload_file(request):
    if request.method == "POST":
        uploaded_file = request.FILES.get("file")

        if not uploaded_file:
            messages.error(request, "No file selected")
            return redirect("upload")

        secure_file_instance = SecureFile.objects.create(
            user=request.user,
            file=uploaded_file
        )

        # 🔒 FORENSIC AUDIT LOG
        AuditLog.objects.create(
            user=request.user,
            file=secure_file_instance,
            action="UPLOAD"
        )

        messages.success(request, "File uploaded successfully")
        return redirect("upload")

    recent_files = SecureFile.objects.filter(
        user=request.user,
        is_deleted=False
    ).order_by("-uploaded_at")[:5]

    return render(request, "upload.html", {
        "recent_files": recent_files
    })
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.utils import timezone

from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from .utils import send_otp

def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get("email")

        if not User.objects.filter(email=email).exists():
            return render(request, "forgot-password.html", {
                "error": "No account found with this email"
            })

        # store email in session
        request.session["reset_email"] = email

        # send OTP
        send_otp(email)

        return redirect("verify_otp")

    return render(request, "forgot-password.html")

from django.shortcuts import render, redirect
from django.utils import timezone
from .models import OTP

MAX_ATTEMPTS = 5

def verify_otp(request):
    email = request.session.get("reset_email")

    if not email:
        return redirect("forgot_password")

    record = OTP.objects.filter(email=email).order_by("-created_at").first()

    if request.method == "POST":
        otp = request.POST.get("otp")

        if not record or not record.is_valid():
            return render(request, "verify-otp.html", {
                "error": "OTP expired. Please resend."
            })

        # initialize attempts if missing
        if not hasattr(record, "attempts"):
            record.attempts = 0

        if record.attempts >= MAX_ATTEMPTS:
            return render(request, "verify-otp.html", {
                "error": "Too many attempts. OTP locked."
            })

        if record.code != otp:
            record.attempts += 1
            record.save()
            return render(request, "verify-otp.html", {
                "error": f"Invalid OTP. Attempts left: {MAX_ATTEMPTS - record.attempts}"
            })

        # ✅ correct OTP
        record.delete()
        request.session["otp_verified"] = True
        return redirect("reset_password")

    return render(request, "verify-otp.html")

import re
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
def reset_password(request):
    email = request.session.get("reset_email")
    otp_verified = request.session.get("otp_verified")

    if not email or not otp_verified:
        return redirect("forgot_password")

    if request.method == "POST":
        password = request.POST.get("password")
        confirm = request.POST.get("confirm_password")

        # mismatch
        if password != confirm:
            return render(request, "reset-password.html", {
                "error": "Passwords do not match"
            })

        # strength checks
        if len(password) < 8:
            return render(request, "reset-password.html", {
                "error": "Password must be at least 8 characters"
            })

        if not re.search(r"[A-Z]", password):
            return render(request, "reset-password.html", {
                "error": "Password must contain one uppercase letter"
            })

        if not re.search(r"[0-9]", password):
            return render(request, "reset-password.html", {
                "error": "Password must contain one number"
            })

        if not re.search(r"[!@#$%^&*]", password):
            return render(request, "reset-password.html", {
                "error": "Password must contain one special character"
            })

        user = User.objects.get(email=email)
        user.password = make_password(password)
        user.save()
        # 📧 SECURITY EMAIL (NEW)
        send_mail(
            subject="Your FogVault password was changed",
            message=(
                "Hello,\n\n"
                "This is a confirmation that your FogVault password "
                "was successfully changed.\n\n"
                f"Time: {timezone.now().strftime('%d %b %Y, %I:%M %p')}\n\n"
                "If this wasn’t you, please reset your password immediately "
                "or contact support.\n\n"
                "— FogVault Security Team"
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=True,
        )


        # cleanup
        request.session.flush()

        return redirect("password_success")

    return render(request, "reset-password.html")

from django.http import JsonResponse
from django.utils import timezone
from datetime import timedelta
from .models import OTP
from .utils import send_otp

def resend_otp(request):
    email = request.session.get("reset_email")

    if not email:
        return JsonResponse({"error": "Session expired"}, status=400)

    last_otp = OTP.objects.filter(email=email).order_by("-created_at").first()

    if last_otp and timezone.now() < last_otp.created_at + timedelta(seconds=60):
        remaining = 60 - int((timezone.now() - last_otp.created_at).total_seconds())
        return JsonResponse({"error": "Wait", "remaining": remaining}, status=429)

    OTP.objects.filter(email=email).delete()
    send_otp(email)

    return JsonResponse({"success": True})
def password_success(request):
    return render(request, "password-success.html")


def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)

            # ✅ SUCCESS LOGIN ALERT
            send_mail(
                subject="New login to your FogVault account",
                message=(
                    f"Hello {user.username},\n\n"
                    "A new login to your FogVault account was detected.\n\n"
                    f"Time: {timezone.now().strftime('%d %b %Y, %I:%M %p')}\n"
                    f"Browser: {request.META.get('HTTP_USER_AGENT', 'Unknown')}\n\n"
                    "If this was you, no action is needed.\n"
                    "If not, please reset your password immediately.\n\n"
                    "— FogVault Security Team"
                ),
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=True,
            )

            return redirect('upload')

        else:
            # 🚨 FAILED LOGIN ALERT (NEW)
            existing_user = User.objects.filter(username=username).first()

            if existing_user:
                send_mail(
                    subject="Failed login attempt on your FogVault account",
                    message=(
                        f"Hello {existing_user.username},\n\n"
                        "Someone tried to log into your FogVault account but failed.\n\n"
                        f"Time: {timezone.now().strftime('%d %b %Y, %I:%M %p')}\n"
                        f"Browser: {request.META.get('HTTP_USER_AGENT', 'Unknown')}\n\n"
                        "If this was NOT you, we strongly recommend changing your password.\n\n"
                        "— FogVault Security Team"
                    ),
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[existing_user.email],
                    fail_silently=True,
                )

            return render(request, 'login.html', {
                'error': 'Invalid credentials'
            })

    return render(request, 'login.html')


def register(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")

        if User.objects.filter(username=username).exists():
            return render(request, "register.html", {"error": "Username already exists"})

        if User.objects.filter(email=email).exists():
            return render(request, "register.html", {"error": "Email already registered"})

        request.session["reg_data"] = {
            "username": username,
            "email": email
        }

        send_otp(email)
        return redirect("verify_register_otp")

    return render(request, "register.html")

def verify_register_otp(request):
    reg_data = request.session.get("reg_data")
    if not reg_data:
        return redirect("register")

    email = reg_data["email"]

    if request.method == "POST":
        otp = request.POST.get("otp")
        record = OTP.objects.filter(email=email).first()

        if not record or not record.is_valid() or record.code != otp:
            record.attempts += 1
            record.save()
            return render(request, "verify-otp.html", {"error": "Invalid OTP"})

        record.delete()
        request.session["otp_verified"] = True
        return redirect("set_password")

    return render(request, "verify-otp.html")

from django.contrib.auth.models import User
from django.conf import settings
from django.core.mail import send_mail

def set_password(request):
    reg_data = request.session.get("reg_data")
    otp_verified = request.session.get("otp_verified")

    if not reg_data or not otp_verified:
        return redirect("register")

    if request.method == "POST":
        password = request.POST.get("password")
        confirm = request.POST.get("confirm_password")

        if password != confirm:
            return render(request, "set-password.html", {
                "error": "Passwords do not match"
            })

        # ✅ CREATE USER (FINAL STEP)
        user = User.objects.create_user(
            username=reg_data["username"],
            email=reg_data["email"],
            password=password
        )

        # ✅ SEND ACCOUNT CREATED EMAIL
        send_mail(
            subject=" Your FogVault account is ready",
            message=(
                f"Hello {user.username},\n\n"
                "Your FogVault account has been successfully created.\n\n"
                "You can now log in securely and start using your vault.\n\n"
                "If this wasn’t you, please contact support immediately.\n\n"
                "— FogVault Security Team"
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=True
        )

        # 🧹 CLEANUP SESSION
        request.session.pop("reg_data", None)
        request.session.pop("otp_verified", None)

        return redirect("login")

    return render(request, "set-password.html")
@login_required
def toggle_star(request, file_id):
    file = get_object_or_404(SecureFile, id=file_id, user=request.user)

    file.is_starred = not file.is_starred
    file.save()

    AuditLog.objects.create(
        user=request.user,
        file=file,
        action="STAR" if file.is_starred else "UNSTAR"
    )

    return redirect("files")
@login_required
def move_to_trash(request, file_id):
    file = get_object_or_404(SecureFile, id=file_id, user=request.user)

    file.is_deleted = True
    file.deleted_at = timezone.now()
    file.save()

    AuditLog.objects.create(
        user=request.user,
        file=file,
        action="DELETE"
    )

    return redirect("files")
@login_required
def restore_file(request, file_id):
    file = get_object_or_404(SecureFile, id=file_id, user=request.user)

    file.is_deleted = False
    file.deleted_at = None
    file.save()

    AuditLog.objects.create(
        user=request.user,
        file=file,
        action="RESTORE"
    )

    return redirect("trash")
@login_required
def permanent_delete(request, file_id):
    file = get_object_or_404(SecureFile, id=file_id, user=request.user)

    AuditLog.objects.create(
        user=request.user,
        file=file,
        action="PERMANENT_DELETE"
    )

    file.delete()
    return redirect("trash")
@login_required
def open_file(request, file_id):
    file = get_object_or_404(SecureFile, id=file_id, user=request.user)

    AuditLog.objects.create(
        user=request.user,
        file=file,
        action="OPEN"
    )

    return FileResponse(file.file.open(), as_attachment=False)
@login_required
def permanent_delete(request, file_id):
    file = get_object_or_404(SecureFile, id=file_id, user=request.user)

    AuditLog.objects.create(
        user=request.user,
        file=file,
        action="PERMANENT_DELETE"
    )

    file.delete()
    return redirect("trash")
@login_required
def restore_file(request, file_id):
    file = get_object_or_404(SecureFile, id=file_id, user=request.user)

    AuditLog.objects.create(
        user=request.user,
        file=file,
        action="RESTORE"
    )

    file.is_deleted = False
    file.deleted_at = None
    file.save()

    return redirect("trash")
@login_required
def move_to_trash(request, file_id):
    file = get_object_or_404(SecureFile, id=file_id, user=request.user)

    AuditLog.objects.create(
        user=request.user,
        file=file,
        action="DELETE"
    )

    file.is_deleted = True
    file.deleted_at = timezone.now()
    file.save()

    return redirect("files")
@login_required
def toggle_star(request, file_id):
    file = get_object_or_404(SecureFile, id=file_id, user=request.user)

    AuditLog.objects.create(
        user=request.user,
        file=file,
        action="STAR" if not file.is_starred else "UNSTAR"
    )

    file.is_starred = not file.is_starred
    file.save()

    return redirect("files")
