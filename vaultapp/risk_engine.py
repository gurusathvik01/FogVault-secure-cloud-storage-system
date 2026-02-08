from django.utils import timezone
from datetime import timedelta
from django.db.models.functions import TruncDate
from django.db.models import Count

from .models import AuditLog, UserSecurity
from .models import SecureFile, AuditLog, UserSecurity


# ============================
# RISK WEIGHTS
# ============================
RISK_WEIGHTS = {
    "LOGIN": 1,
    "UPLOAD": 1,
    "DELETE": 5,
    "PERMANENT_DELETE": 10,
    "DISABLE_USER": 8,
    "ENABLE_USER": 2,
    "FORCE_LOGOUT": 5,
}


# ============================
# DAILY RISK TREND
# ============================
def calculate_user_risk_trend(user):
    logs = (
        AuditLog.objects
        .filter(user=user)
        .annotate(day=TruncDate("timestamp"))
        .values("day", "action")
        .annotate(count=Count("id"))
        .order_by("day")
    )

    trend = {}

    for l in logs:
        day = l["day"].strftime("%d %b")
        trend.setdefault(day, 0)
        trend[day] += RISK_WEIGHTS.get(l["action"], 0) * l["count"]

    return trend


# ============================
# CORE RISK ENGINE
# ============================
def calculate_user_risk(user):
    logs = AuditLog.objects.filter(user=user)

    score = 0
    reasons = []

    login_count = logs.filter(action="LOGIN").count()
    upload_count = logs.filter(action="UPLOAD").count()
    delete_count = logs.filter(action="DELETE").count()
    perm_delete_count = logs.filter(action="PERMANENT_DELETE").count()

    score += login_count
    score += upload_count
    score += delete_count * 5
    score += perm_delete_count * 10

    if delete_count >= 5:
        reasons.append("High number of delete actions")

    if perm_delete_count > 0:
        reasons.append("Permanent delete detected")

    if logs.filter(action__icontains="DISABLE").exists():
        score += 20
        reasons.append("Admin intervention recorded")

    # Night activity (12AM – 5AM)
    night_activity = logs.filter(timestamp__hour__lte=5).count()
    if night_activity >= 3:
        score += 8
        reasons.append("Suspicious night activity")

    # Final level
    if score < 20:
        level = "LOW"
    elif score < 50:
        level = "MEDIUM"
    elif score < 80:
        level = "HIGH"
    else:
        level = "CRITICAL"

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
    }


# ============================
# AUTO SECURITY ACTIONS
# ============================
def apply_auto_actions(user):
    risk = calculate_user_risk(user)

    security, _ = UserSecurity.objects.get_or_create(user=user)

    # AUTO DISABLE IF CRITICAL
    if risk["score"] >= 80:
        user.is_active = False
        user.save()

        security.disabled_until = timezone.now() + timedelta(days=1)
        security.save()

    # AUTO FLAG
    if "Suspicious night activity" in risk["reasons"]:
        security.is_flagged = True
        security.save()

    return risk
