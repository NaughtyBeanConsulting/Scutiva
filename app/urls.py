from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.urls import include, path

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", include("dashboard.urls")),
    path("accounts/", include("accounts.urls")),
    path("servers/", include("servers.urls")),
    path("scans/", include("scanners.urls")),
    path("vulnerabilities/", include("vulnerabilities.urls")),
    path("sboms/", include("sboms.urls")),
    path("reports/", include("reports.urls")),
    path("settings/", include("core.urls")),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
