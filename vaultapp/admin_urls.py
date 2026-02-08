from django.urls import path
from . import admin_views
from .admin_views import admin_logs

urlpatterns = [
    # Auth
    path("login/", admin_views.admin_login, name="admin_login"),
    path("logout/", admin_views.admin_logout, name="admin_logout"),

    # Pages
    path("dashboard/", admin_views.admin_dashboard, name="admin_dashboard"),
    path("users/", admin_views.admin_users, name="admin_users"),
    path("logs/", admin_views.admin_logs, name="admin_logs"),
    path("trash/", admin_views.admin_trash, name="admin_trash"),
    path("audit/", admin_views.admin_audit_timeline, name="admin_audit"),

    # User actions
    path("user/disable/<int:user_id>/", admin_views.admin_disable_user, name="admin_disable_user"),
    path("user/enable/<int:user_id>/", admin_views.admin_enable_user, name="admin_enable_user"),
    path("user/delete/<int:user_id>/", admin_views.admin_delete_user, name="admin_delete_user"),
path(
    "user/logout/<int:user_id>/",
    admin_views.admin_force_logout,
    name="admin_force_logout"
),

    # Risk graph
    path(
        "user/risk/<int:user_id>/",
        admin_views.admin_user_risk_graph,
        name="admin_user_risk"
    ),
    # 🔐 ADVANCED USER SECURITY ACTIONS

path(
    "user/force-logout/<int:user_id>/",
    admin_views.admin_force_logout,
    name="admin_force_logout"
),

path(
    "user/temp-disable/<int:user_id>/<int:days>/",
    admin_views.admin_temp_disable,
    name="admin_temp_disable"
),

path(
    "user/flag/<int:user_id>/",
    admin_views.admin_flag_user,
    name="admin_flag_user"
),
path("logs/", admin_logs, name="admin_logs"),

]
