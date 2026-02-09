from django.urls import path
from . import views
from django.urls import path
from . import views

from django.views.generic import TemplateView
from django.urls import path, include


 
urlpatterns = [
    path('', views.home, name='home'),
    path('login/', views.user_login, name='login'),
    path('logout/', views.user_logout, name='logout'),
    path('upload/', views.upload_file, name='upload'),
    path('files/', views.files_page, name='files'),
    path('history/', views.history_page, name='history'),
    path('trash/', views.trash_page, name='trash'),
    path("star/<int:file_id>/", views.toggle_star, name="toggle_star"),
    path("starred/", views.starred_page, name="starred"),
    path("bulk/delete/", views.bulk_delete, name="bulk_delete"),
    path("bulk/star/", views.bulk_star),
    path('trash/delete/<int:file_id>/', views.move_to_trash, name='move_to_trash'),
    path('trash/restore/<int:file_id>/', views.restore_file, name='restore_file'),
    path('trash/permanent/<int:file_id>/', views.permanent_delete, name='permanent_delete'),
    path("bulk/restore/", views.bulk_restore, name="bulk_restore"),
    path("bulk/permanent-delete/", views.bulk_permanent_delete, name="bulk_permanent_delete"),
    path("open/<int:file_id>/", views.open_file, name="open_file"),
    path("audit/", views.audit_page, name="audit"),
      path("register/", views.register, name="register"),
    path("verify-register-otp/", views.verify_register_otp, name="verify_register_otp"),

    path("forgot-password/", views.forgot_password, name="forgot_password"),
    path("reset-password/", views.reset_password, name="reset_password"),

    path("verify-otp/", views.verify_otp, name="verify_otp"),
    path("resend-otp/", views.resend_otp, name="resend_otp"),
    path("password-success/", views.password_success, name="password_success"),

path("reset-success/", TemplateView.as_view(
    template_name="reset-success.html"
), name="reset_success"),

path("set-password/", views.set_password, name="set_password"),
path("open/<int:file_id>/", views.open_file, name="open_file"),
path("admin-panel/", include("vaultapp.admin_urls")),

]
