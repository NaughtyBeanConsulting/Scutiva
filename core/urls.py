from django.urls import path

from .views import (
    DefaultScanProfileUpdateView,
    OrganisationUpdateView,
    PasswordUpdateView,
    ProfileUpdateView,
    SettingsView,
)


app_name = "core"

urlpatterns = [
    path("", SettingsView.as_view(), name="settings"),
    path("profile/", ProfileUpdateView.as_view(), name="profile-update"),
    path("password/", PasswordUpdateView.as_view(), name="password-update"),
    path("organisation/", OrganisationUpdateView.as_view(), name="org-update"),
    path("scan-profile/", DefaultScanProfileUpdateView.as_view(), name="scan-profile-update"),
]
