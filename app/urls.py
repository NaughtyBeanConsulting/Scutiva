from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
from django.urls import include, path
from django.views.generic import RedirectView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("favicon-96x96.png", RedirectView.as_view(url=settings.STATIC_URL + "img/favicon/favicon-96x96.png", permanent=False)),
    path("favicon.svg", RedirectView.as_view(url=settings.STATIC_URL + "img/favicon/favicon.svg", permanent=False)),
    path("favicon.ico", RedirectView.as_view(url=settings.STATIC_URL + "img/favicon/favicon.ico", permanent=False)),
    path("apple-touch-icon.png", RedirectView.as_view(url=settings.STATIC_URL + "img/favicon/apple-touch-icon.png", permanent=False)),
    path("site.webmanifest", RedirectView.as_view(url=settings.STATIC_URL + "img/favicon/site.webmanifest", permanent=False)),
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
