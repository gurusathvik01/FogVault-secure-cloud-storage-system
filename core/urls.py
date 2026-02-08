from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path("admin/", admin.site.urls),          # Django admin (KEEP)
    path("", include("vaultapp.urls")),       # User side
    path("admin-panel/", include("vaultapp.admin_urls")),  # Admin panel
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
