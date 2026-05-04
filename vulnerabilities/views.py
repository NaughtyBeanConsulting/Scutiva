from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render
from django.views import View
from django.views.generic import DetailView, ListView

from .forms import VulnerabilityTriageForm
from .models import VulnerabilityFinding


class VulnerabilityListView(LoginRequiredMixin, ListView):
    model = VulnerabilityFinding
    template_name = "vulnerabilities/list.html"
    context_object_name = "findings"
    paginate_by = 25

    def get_template_names(self):
        if self.request.headers.get("HX-Request"):
            return ["vulnerabilities/_table.html"]
        return [self.template_name]

    def get_queryset(self):
        queryset = VulnerabilityFinding.objects.select_related("server", "application")
        severity = self.request.GET.get("severity")
        status = self.request.GET.get("status")
        scanner = self.request.GET.get("scanner")
        cve_id = self.request.GET.get("cve_id")

        if severity:
            queryset = queryset.filter(severity=severity)
        if status:
            queryset = queryset.filter(status=status)
        if scanner:
            queryset = queryset.filter(source_scanner__iexact=scanner)
        if cve_id:
            queryset = queryset.filter(cve_id__icontains=cve_id)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["severity_choices"] = VulnerabilityFinding.Severity.choices
        context["status_choices"] = VulnerabilityFinding.Status.choices
        context["filters"] = self.request.GET
        return context


class VulnerabilityDetailView(LoginRequiredMixin, DetailView):
    model = VulnerabilityFinding
    template_name = "vulnerabilities/detail.html"
    context_object_name = "finding"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["triage_form"] = kwargs.get("triage_form", VulnerabilityTriageForm(instance=self.object))
        return context


class VulnerabilityTriageView(LoginRequiredMixin, View):
    def post(self, request, pk, *args, **kwargs):
        finding = VulnerabilityFinding.objects.get(pk=pk)
        form = VulnerabilityTriageForm(request.POST, instance=finding)
        if not form.is_valid():
            response = render(request, "vulnerabilities/_triage_panel.html", {"finding": finding, "triage_form": form})
            response.status_code = 422
            return response
        form.save()
        messages.success(request, f"Updated triage for {finding.cve_id}.")
        return render(request, "vulnerabilities/_triage_panel.html", {"finding": finding, "triage_form": VulnerabilityTriageForm(instance=finding)})
