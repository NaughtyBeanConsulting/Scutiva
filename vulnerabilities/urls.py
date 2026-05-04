from django.urls import path

from .views import VulnerabilityDetailView, VulnerabilityListView, VulnerabilityTriageView


app_name = "vulnerabilities"

urlpatterns = [
    path("", VulnerabilityListView.as_view(), name="list"),
    path("<int:pk>/triage/", VulnerabilityTriageView.as_view(), name="triage"),
    path("<int:pk>/", VulnerabilityDetailView.as_view(), name="detail"),
]