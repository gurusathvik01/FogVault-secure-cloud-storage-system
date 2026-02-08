from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.models import User
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone
from datetime import timedelta
from django.http import Http404

from .models import SecureFile, AuditLog
from .utils import admin_required
from vaultapp.risk_engine import calculate_user_risk, calculate_user_risk_trend

from vaultapp.risk_engine import calculate_user_risk
from django.db.models import Count
from django.db.models.functions import TruncDate
from django.contrib.sessions.models import Session
from django.utils import timezone
from datetime import timedelta
from .models import UserSecurity
from django.contrib.auth import logout
from django.contrib import messages
from django.shortcuts import get_object_or_404, redirect
from django.contrib.auth.models import User

from .models import AuditLog
from .utils import admin_required

from django.shortcuts import render
from django.utils import timezone
from datetime import timedelta
from .models import AuditLog
from .utils import admin_required
from django.utils import timezone
from vaultapp.models import SecureFile
from vaultapp.utils import admin_required
from django.contrib.auth.decorators import login_required
from .models import SecureFile, AuditLog, UserSecurity


@login_required
def move_to_trash(request, file_id):
    f = get_object_or_404(SecureFile, id=file_id, user=request.user)

    f.is_deleted = True
    f.deleted_at = timezone.now()
    f.deleted_by = request.user
    f.save()

    AuditLog.objects.create(
        user=request.user,
        file=f,
        action="DELETE"
    )

    return redirect("files")


@admin_required
def admin_trash(request):
    files = SecureFile.objects.filter(
        is_deleted=True
    ).select_related("user", "deleted_by").order_by("-deleted_at")

    return render(request, "admin-trash.html", {
        "files": files,
        "now": timezone.now()
    })


@admin_required
def admin_user_risk_graph(request, user_id):
    user = get_object_or_404(User, id=user_id)

    trend = calculate_user_risk_trend(user)
    trend_labels = list(trend.keys())
    trend_scores = list(trend.values())

    risk = calculate_user_risk(user)
    timeline = AuditLog.objects.filter(user=user).order_by("-timestamp")[:30]

    return render(request, "admin-user-risk.html", {
        "target_user": user,
        "trend_labels": trend_labels,
        "trend_scores": trend_scores,
        "risk": risk,
        "timeline": timeline,
    })
@admin_required
def admin_user_risk_graph(request, user_id):
    user = get_object_or_404(User, id=user_id)

    trend = calculate_user_risk_trend(user)
    trend_labels = list(trend.keys())
    trend_scores = list(trend.values())

    risk = calculate_user_risk(user)
    timeline = AuditLog.objects.filter(user=user).order_by("-timestamp")[:30]

    return render(request, "admin-user-risk.html", {
        "target_user": user,
        "trend_labels": trend_labels,
        "trend_scores": trend_scores,
        "risk": risk,
        "timeline": timeline,
    })
@admin_required
def admin_user_risk_graph(request, user_id):
    user = get_object_or_404(User, id=user_id)

    trend = calculate_user_risk_trend(user)
    trend_labels = list(trend.keys())
    trend_scores = list(trend.values())

    risk = calculate_user_risk(user)
    timeline = AuditLog.objects.filter(user=user).order_by("-timestamp")[:30]

    return render(request, "admin-user-risk.html", {
        "target_user": user,
        "trend_labels": trend_labels,
        "trend_scores": trend_scores,
        "risk": risk,
        "timeline": timeline,
    })
@admin_required
def admin_temp_disable(request, user_id, days):
    user = get_object_or_404(User, id=user_id)

    security, _ = UserSecurity.objects.get_or_create(user=user)
    security.disabled_until = timezone.now() + timedelta(days=days)
    security.save()

    user.is_active = False
    user.save()

    AuditLog.objects.create(
        user=request.user,
        action=f"TEMP_DISABLE_{days}D",
        file=None
    )

    messages.warning(request, f"User disabled for {days} days")
    return redirect("admin_users")
@admin_required
def admin_flag_user(request, user_id):
    user = get_object_or_404(User, id=user_id)

    security, _ = UserSecurity.objects.get_or_create(user=user)
    security.is_flagged = True
    security.save()

    AuditLog.objects.create(
        user=request.user,
        action="FLAG_USER",
        file=None
    )

    messages.error(request, "User flagged as suspicious")
    return redirect("admin_users")

# =========================
# ADMIN LOGIN / LOGOUT
# =========================

def admin_login(request):
    if request.method == "POST":
        user = authenticate(
            request,
            username=request.POST.get("username"),
            password=request.POST.get("password")
        )

        if user and user.is_staff:
            login(request, user)
            return redirect("admin_dashboard")

        messages.error(request, "Invalid admin credentials")

    return render(request, "admin-login.html")


def admin_logout(request):
    logout(request)
    return redirect("admin_login")


# =========================
# ADMIN DASHBOARD
# =========================


@admin_required
def admin_dashboard(request):
    days = int(request.GET.get("days", 30))
    since = timezone.now() - timedelta(days=days)

    logs = AuditLog.objects.filter(timestamp__gte=since)
    users = User.objects.all()

    # -------------------------
    # 🔥 RISK INTELLIGENCE
    # -------------------------
    high_risk_users = 0
    total_risk = 0

    for user in users:
        risk = calculate_user_risk(user)
        total_risk += risk["score"]
        if risk["level"] in ["HIGH", "CRITICAL"]:
            high_risk_users += 1

    avg_risk = round(total_risk / max(users.count(), 1))

    auto_disabled = AuditLog.objects.filter(
        action__icontains="DISABLE"
    ).count()

    suspicious_days = (
        logs
        .annotate(day=TruncDate("timestamp"))
        .values("day")
        .annotate(count=Count("id"))
        .filter(count__gte=10)
        .count()
    )

    # -------------------------
    # 📈 TOP 5 RISKY USERS
    # -------------------------
    risky_users = []
    for user in users:
        risk = calculate_user_risk(user)
        risky_users.append({
            "user": user,
            "score": risk["score"],
            "level": risk["level"]
        })

    top_risky_users = sorted(
        risky_users,
        key=lambda x: x["score"],
        reverse=True
    )[:5]

    # -------------------------
    # 🔴 RISK HEATMAP DATA
    # -------------------------
    heatmap_data = (
        logs
        .annotate(day=TruncDate("timestamp"))
        .values("day")
        .annotate(risk=Count("id"))
        .order_by("day")
    )

    heatmap_labels = [d["day"].strftime("%d %b") for d in heatmap_data]
    heatmap_scores = [d["risk"] for d in heatmap_data]

    # -------------------------
    # 🛡️ SYSTEM HEALTH
    # -------------------------
    storage_used = SecureFile.objects.count()
    last_backup = "24 Jan 2026"   # static for now
    integrity_status = "OK"       # later automate

    return render(request, "admin-dashboard.html", {
        "total_users": users.count(),
        "admins": users.filter(is_staff=True).count(),
        "total_logs": logs.count(),

        # Widgets
        "high_risk_users": high_risk_users,
        "auto_disabled": auto_disabled,
        "suspicious_days": suspicious_days,
        "avg_risk": avg_risk,

        # Lists
        "top_risky_users": top_risky_users,

        # Heatmap
        "heatmap_labels": heatmap_labels,
        "heatmap_scores": heatmap_scores,

        # Health
        "storage_used": storage_used,
        "last_backup": last_backup,
        "integrity_status": integrity_status,
    })


# =========================
# ADMIN USERS (SINGLE SOURCE)
# =========================

@admin_required
def admin_users(request):
    users = User.objects.all().order_by("-date_joined")
    risk_map = {}

    for user in users:
        risk_map[user.id] = calculate_user_risk(user)

    return render(request, "admin-users.html", {
        "users": users,
        "risk_map": risk_map
    })


# =========================
# ENABLE / DISABLE / DELETE
# =========================

@admin_required
def admin_enable_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    user.is_active = True
    user.save()

    AuditLog.objects.create(user=request.user, action="ENABLE_USER", file=None)
    messages.success(request, f"{user.username} enabled.")
    return redirect("admin_users")


@admin_required
def admin_disable_user(request, user_id):
    user = get_object_or_404(User, id=user_id)

    if user.is_superuser:
        messages.error(request, "Cannot disable superuser.")
        return redirect("admin_users")

    user.is_active = False
    user.save()

    AuditLog.objects.create(user=request.user, action="DISABLE_USER", file=None)
    messages.warning(request, f"{user.username} disabled.")
    return redirect("admin_users")


@admin_required
def admin_delete_user(request, user_id):
    user = get_object_or_404(User, id=user_id)

    if user.is_superuser:
        messages.error(request, "Cannot delete superuser.")
        return redirect("admin_users")

    AuditLog.objects.create(user=request.user, action="DELETE_USER", file=None)
    user.delete()
    return redirect("admin_users")


# =========================
# USER RISK GRAPH
# =========================

@admin_required
def admin_user_risk_graph(request, user_id):
    user = get_object_or_404(User, id=user_id)

    trend = calculate_user_risk_trend(user)


    return render(request, "admin-user-risk.html", {
        "target_user": user,
        "trend_labels": list(trend.keys()),
        "trend_scores": list(trend.values()),
    })


# =========================
# LOGS / TRASH / AUDIT
# =========================

@admin_required
def admin_logs(request):
    return render(request, "admin-logs.html", {
        "logs": AuditLog.objects.select_related("user", "file").order_by("-timestamp")[:500]
    })


@admin_required
def admin_trash(request):
    return render(request, "admin-trash.html", {
        "files": SecureFile.objects.filter(is_deleted=True).order_by("-deleted_at")
    })


@admin_required
def admin_audit_timeline(request):
    logs = AuditLog.objects.select_related("user", "file").order_by("-timestamp")

    if request.GET.get("user"):
        logs = logs.filter(user__id=request.GET["user"])
    if request.GET.get("action"):
        logs = logs.filter(action=request.GET["action"])
    if request.GET.get("start"):
        logs = logs.filter(timestamp__date__gte=request.GET["start"])
    if request.GET.get("end"):
        logs = logs.filter(timestamp__date__lte=request.GET["end"])

    return render(request, "admin-audit.html", {
        "logs": logs[:500],
        "users": User.objects.all(),
    })
@admin_required
def admin_user_risk_graph(request, user_id):
    user = get_object_or_404(User, id=user_id)

    logs = AuditLog.objects.filter(user=user).order_by("timestamp")

    trend_labels = []
    trend_scores = []
    running_score = 0

    for log in logs:
        if log.action == "LOGIN":
            running_score += 1
        elif log.action == "UPLOAD":
            running_score += 1
        elif log.action == "DELETE":
            running_score += 5
        elif log.action == "PERMANENT_DELETE":
            running_score += 10
        elif "DISABLE" in log.action:
            running_score += 5

        trend_labels.append(log.timestamp.strftime("%d %b"))
        trend_scores.append(running_score)

    return render(request, "admin-user-risk.html", {
        "target_user": user,
        "trend_labels": trend_labels,
        "trend_scores": trend_scores,
        "has_data": logs.exists(),
    })



@admin_required
def admin_force_logout(request, user_id):
    user = get_object_or_404(User, id=user_id)

    # Log the action
    AuditLog.objects.create(
        user=request.user,
        action="FORCE_LOGOUT",
        file=None
    )

    messages.warning(
        request,
        f"{user.username} has been force logged out."
    )

    # NOTE:
    # Django cannot directly kill another user's session
    # This is the industry-standard workaround:
    # mark it as security action + require re-login
    user.last_login = None
    user.save()

    return redirect("admin_users")
from django.contrib.sessions.models import Session
from django.utils import timezone

@admin_required
def admin_force_logout(request, user_id):
    user = get_object_or_404(User, id=user_id)

    # Delete all active sessions for this user
    sessions = Session.objects.filter(expire_date__gte=timezone.now())
    for session in sessions:
        data = session.get_decoded()
        if data.get("_auth_user_id") == str(user.id):
            session.delete()

    AuditLog.objects.create(
        user=request.user,
        action=f"FORCE_LOGOUT:{user.username}",
        file=None
    )

    messages.warning(request, f"{user.username} was force logged out.")
    return redirect("admin_users")
@admin_required
def admin_temp_disable(request, user_id, days):
    user = get_object_or_404(User, id=user_id)

    user.is_active = False
    user.save()

    AuditLog.objects.create(
        user=request.user,
        action=f"TEMP_DISABLE_{days}D:{user.username}",
        file=None
    )

    messages.warning(request, f"{user.username} disabled for {days} days.")
    return redirect("admin_users")
@admin_required
def admin_flag_user(request, user_id):
    user = get_object_or_404(User, id=user_id)

    AuditLog.objects.create(
        user=request.user,
        action=f"FLAG_USER:{user.username}",
        file=None
    )

    messages.error(request, f"{user.username} has been flagged.")
    return redirect("admin_users")

@admin_required
def admin_logs(request):
    logs = AuditLog.objects.all().order_by("-timestamp")

    # 🔍 FILTERS
    action = request.GET.get("action")
    risk_only = request.GET.get("risk")
    admin_only = request.GET.get("admin")
    days = request.GET.get("days")

    if action:
        logs = logs.filter(action__icontains=action)

    if admin_only:
        logs = logs.filter(user__is_staff=True)

    if risk_only:
        logs = logs.filter(action__in=[
            "DELETE",
            "PERMANENT_DELETE",
            "DISABLE_USER",
            "TEMP_DISABLE_1D",
            "TEMP_DISABLE_7D",
            "FLAG_USER",
        ])

    if days:
        since = timezone.now() - timedelta(days=int(days))
        logs = logs.filter(timestamp__gte=since)

    return render(request, "admin-logs.html", {
        "logs": logs,
        "active_action": action or "",
        "risk_only": risk_only,
        "admin_only": admin_only,
        "days": days or "",
    })
