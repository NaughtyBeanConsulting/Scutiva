from django.urls import path

from .views import ReportCreateView, ReportDownloadView, ReportListView


app_name = "reports"

urlpatterns = [
    path("", ReportListView.as_view(), name="list"),
    path("new/", ReportCreateView.as_view(), name="create"),
    path("<int:pk>/download/", ReportDownloadView.as_view(), name="download"),
]
