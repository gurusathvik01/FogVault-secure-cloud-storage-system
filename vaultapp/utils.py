from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages
from .models import SecureFile, AuditLog, UserSecurity
from django.core.mail import send_mail
from .models import OTP
import random

from django.core.mail import send_mail
from .models import OTP

def send_otp(email):
    OTP.objects.filter(email=email).delete()
    code = OTP.generate()
    OTP.objects.create(email=email, code=code)

    send_mail(
        subject="Your FogVault OTP",
        message=f"Your OTP is {code}. Valid for 5 minutes.",
        from_email="noreply@fogvault.com",
        recipient_list=[email],
        fail_silently=False,
    )

def send_otp(email):
    code = str(random.randint(100000, 999999))

    OTP.objects.filter(email=email).delete()
    OTP.objects.create(email=email, code=code)

    send_mail(
        "Your OTP Code",
        f"Your OTP is {code}. Valid for 5 minutes.",
        "noreply@fogvault.com",
        [email],
        fail_silently=False
    )

def admin_required(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect("admin_login")

        if not request.user.is_staff:
            messages.error(request, "Admin access required.")
            return redirect("/")

        return view_func(request, *args, **kwargs)

    return wrapper
import random
from django.core.mail import send_mail
from django.conf import settings
from .models import OTP

def send_otp(email):
    # Delete old OTPs
    OTP.objects.filter(email=email).delete()

    # Generate 6-digit OTP
    code = str(random.randint(100000, 999999))

    # Save OTP
    OTP.objects.create(email=email, code=code)


import random
from django.core.mail import send_mail
from django.conf import settings
from .models import OTP

def send_otp(email):
    OTP.objects.filter(email=email).delete()

    code = str(random.randint(100000, 999999))
    OTP.objects.create(email=email, code=code)

    send_mail(
        subject="Your FogVault OTP",
        message=f"Your OTP is {code}. It is valid for 5 minutes.",
        from_email=settings.EMAIL_HOST_USER,
        recipient_list=[email],
        fail_silently=True
    )
