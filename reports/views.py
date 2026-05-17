import mimetypes
from pathlib import Path

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import FileResponse, Http404
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View
from django.views.generic import ListView

from servers.models import Application, Server
from scanners.models import ScanProfile

from .models import ReportArtifact
from .services import generate_report


class ReportListView(LoginRequiredMixin, ListView):
    model = ReportArtifact
    template_name = "reports/list.html"
    context_object_name = "reports"
    paginate_by = 20

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["report_types"] = ReportArtifact.ReportType.choices
        context["output_formats"] = [
            (ReportArtifact.OutputFormat.CSV, "CSV"),
            (ReportArtifact.OutputFormat.JSON, "JSON"),
        ]
        context["servers"] = Server.objects.filter(is_active=True).order_by("name")
        context["applications"] = Application.objects.select_related("server").order_by("server__name", "name")
        return context


class ReportCreateView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        report_type = request.POST.get("report_type", "")
        output_format = request.POST.get("output_format", "")
        name = request.POST.get("name", "").strip()

        valid_types = {c[0] for c in ReportArtifact.ReportType.choices}
        valid_formats = {ReportArtifact.OutputFormat.CSV, ReportArtifact.OutputFormat.JSON}

        if report_type not in valid_types or output_format not in valid_formats:
            messages.error(request, "Invalid report type or format.")
            return redirect("reports:list")

        if not name:
            name = f"{dict(ReportArtifact.ReportType.choices).get(report_type, report_type)} — {output_format.upper()}"

        filters = {}
        if report_type == ReportArtifact.ReportType.SERVER:
            server_id = request.POST.get("server_id")
            if server_id:
                filters["server_id"] = server_id
        elif report_type == ReportArtifact.ReportType.APPLICATION:
            app_id = request.POST.get("application_id")
            if app_id:
                filters["application_id"] = app_id

        report = ReportArtifact.objects.create(
            name=name,
            report_type=report_type,
            output_format=output_format,
            filters=filters,
            generated_by=request.user,
        )
        try:
            generate_report(report)
            messages.success(request, f"Report \"{report.name}\" generated successfully.")
        except Exception as exc:
            report.delete()
            messages.error(request, f"Report generation failed: {exc}")

        return redirect("reports:list")


class ReportDownloadView(LoginRequiredMixin, View):
    def get(self, request, pk, *args, **kwargs):
        report = get_object_or_404(ReportArtifact, pk=pk)
        if not report.file_path:
            raise Http404("No file generated for this report.")
        file_path = Path(report.file_path).resolve()
        if not file_path.exists() or not file_path.is_file():
            raise Http404("Report file not found on disk.")
        content_type, _ = mimetypes.guess_type(str(file_path))
        response = FileResponse(open(file_path, "rb"), content_type=content_type or "application/octet-stream")
        response["Content-Disposition"] = f'attachment; filename="{file_path.name}"'
        return response
