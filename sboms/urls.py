from django.urls import path

from .views import SBOMListView


app_name = "sboms"

urlpatterns = [
    path("", SBOMListView.as_view(), name="list"),
]