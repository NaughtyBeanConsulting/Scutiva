from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView

from .models import SBOMArtifact


class SBOMListView(LoginRequiredMixin, ListView):
    model = SBOMArtifact
    template_name = "sboms/list.html"
    context_object_name = "sboms"
    paginate_by = 20

    def get_queryset(self):
        return SBOMArtifact.objects.select_related("server", "application", "related_scan")
