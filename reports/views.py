from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView

from .models import ReportArtifact


class ReportListView(LoginRequiredMixin, ListView):
    model = ReportArtifact
    template_name = "reports/list.html"
    context_object_name = "reports"
    paginate_by = 20
