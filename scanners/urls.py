from django.urls import path

from .views import (
    CancelScanJobView,
    InstallerScriptView,
    LiveMonitorView,
    QuickQueueScanView,
    QueueScanJobView,
    QueueServerJobView,
    RetryScanJobView,
    ScanJobArtifactDownloadView,
    ScanJobDetailView,
    ScanJobListView,
    ScanJobTableView,
    ScanProfileCreateView,
    ScanProfileUpdateView,
)


app_name = "scanners"

urlpatterns = [
    path("", ScanJobListView.as_view(), name="list"),
    path("live/", LiveMonitorView.as_view(), name="live"),
    path("jobs/table/", ScanJobTableView.as_view(), name="jobs-table"),
    path("jobs/<int:pk>/", ScanJobDetailView.as_view(), name="job-detail"),
    path("jobs/<int:pk>/artifacts/<path:filename>/", ScanJobArtifactDownloadView.as_view(), name="job-artifact-download"),
    path("jobs/<int:pk>/cancel/", CancelScanJobView.as_view(), name="job-cancel"),
    path("jobs/<int:pk>/retry/", RetryScanJobView.as_view(), name="job-retry"),
    path("quick/<str:target_type>/<int:target_id>/", QuickQueueScanView.as_view(), name="quick-queue"),
    path("queue/", QueueScanJobView.as_view(), name="queue"),
    path("profiles/new/", ScanProfileCreateView.as_view(), name="profile-create"),
    path("profiles/<int:pk>/edit/", ScanProfileUpdateView.as_view(), name="profile-edit"),
    path("servers/<int:server_id>/<str:queue_name>/", QueueServerJobView.as_view(), name="server-job"),
    path("installer-script/", InstallerScriptView.as_view(), name="installer-script"),
]