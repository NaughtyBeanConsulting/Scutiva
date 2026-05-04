from django.urls import path

from .views import (
    ApplicationListView,
    ServerActivityView,
    ServerCreateView,
    ServerDetailView,
    ServerListView,
    ServerUpdateView,
    TestConnectionView,
)


app_name = "servers"

urlpatterns = [
    path("", ServerListView.as_view(), name="list"),
    path("new/", ServerCreateView.as_view(), name="create"),
    path("applications/", ApplicationListView.as_view(), name="applications"),
    path("test-connection/", TestConnectionView.as_view(), name="test-connection"),
    path("<int:pk>/activity/", ServerActivityView.as_view(), name="activity"),
    path("<int:pk>/edit/", ServerUpdateView.as_view(), name="edit"),
    path("<int:pk>/", ServerDetailView.as_view(), name="detail"),
]