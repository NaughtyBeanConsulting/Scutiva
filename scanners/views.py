import json
from pathlib import Path
from mimetypes import guess_type

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.conf import settings
from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse_lazy
from django.views import View
from django.views.generic import CreateView, ListView, TemplateView, UpdateView
from django.utils import timezone

from datetime import timedelta

from servers.models import Application, Server

from .forms import QueueScanJobForm, ScanProfileForm
from .models import ComplianceFinding, ScanJob, ScanProfile
from .services import enqueue_scan_job, generate_installer_script, queue_scheduled_scans, update_job_progress


JOB_OUTPUT_PREVIEW_LIMIT = 5000


def get_stage_label(stage_value):
    try:
        return ScanJob.Stage(stage_value).label
    except Exception:
        return stage_value or "Unknown"


def get_job_output_directory(job):
    if not job.raw_output_path:
        return None
    try:
        output_dir = Path(job.raw_output_path).resolve()
        media_root = Path(settings.MEDIA_ROOT).resolve()
    except OSError:
        return None
    if output_dir != media_root and media_root not in output_dir.parents:
        return None
    if not output_dir.exists() or not output_dir.is_dir():
        return None
    return output_dir


def get_job_output_previews(job):
    output_dir = get_job_output_directory(job)
    if not output_dir:
        return []

    previews = []
    for path in sorted(output_dir.iterdir()):
        if not path.is_file():
            continue
        content = path.read_text(encoding="utf-8", errors="replace")
        previews.append(
            {
                "name": path.name,
                "size": path.stat().st_size,
                "download_name": path.name,
                "preview": content[:JOB_OUTPUT_PREVIEW_LIMIT],
                "truncated": len(content) > JOB_OUTPUT_PREVIEW_LIMIT,
            }
        )
    return previews


def get_job_detail_context(job):
    progress_context = job.progress_context or {}
    compliance_findings = list(
        ComplianceFinding.objects.filter(scan_job=job)
        .order_by("-last_seen", "-created_at")[:25]
        .values("source_scanner", "benchmark", "control_id", "title", "severity", "resource", "description", "remediation")
    )
    progress_events = []
    for event in reversed(progress_context.get("events", [])):
        progress_events.append(
            {
                **event,
                "stage_label": get_stage_label(event.get("stage")),
            }
        )

    return {
        "job": job,
        "progress_context": progress_context,
        "progress_events": progress_events,
        "progress_context_json": json.dumps(progress_context, indent=2, sort_keys=True),
        "parsed_findings_json": json.dumps(job.parsed_findings or [], indent=2, sort_keys=True),
        "compliance_findings": compliance_findings,
        "compliance_findings_json": json.dumps(compliance_findings, indent=2, sort_keys=True),
        "output_files": get_job_output_previews(job),
    }


def get_scan_jobs_queryset(limit=None):
    queryset = ScanJob.objects.select_related("server", "application", "scan_profile").order_by("-created_at")
    if limit:
        return queryset[:limit]
    return queryset


def build_queue_form(initial=None):
    return QueueScanJobForm(initial=initial or None)


def render_action_response(request, message, *, queue_form=None):
    return render(
        request,
        "scanners/_quick_queue_response.html",
        {
            "message": message,
            "queue_form": queue_form or build_queue_form(),
            "scan_jobs": get_scan_jobs_queryset(limit=20),
            **get_live_monitor_context(),
        },
    )


def get_live_monitor_context():
    queryset = ScanJob.objects.all()
    active_statuses = [ScanJob.Status.QUEUED, ScanJob.Status.PROCESSING]
    recent_cutoff = timezone.now() - timedelta(minutes=10)
    active_jobs = queryset.select_related("server", "application").filter(status__in=active_statuses).order_by("-created_at")[:5]
    recent_jobs = queryset.select_related("server", "application").filter(
        status__in=[
            ScanJob.Status.COMPLETED,
            ScanJob.Status.COMPLETED_WITH_WARNINGS,
            ScanJob.Status.FAILED,
            ScanJob.Status.CANCELLED,
        ],
        ended_at__gte=recent_cutoff,
    ).order_by("-ended_at")[:4]
    return {
        "live_summary": {
            "queued": queryset.filter(status=ScanJob.Status.QUEUED).count(),
            "processing": queryset.filter(status=ScanJob.Status.PROCESSING).count(),
            "completed_recent": queryset.filter(status=ScanJob.Status.COMPLETED, ended_at__gte=recent_cutoff).count(),
            "failed_recent": queryset.filter(status=ScanJob.Status.FAILED, ended_at__gte=recent_cutoff).count(),
        },
        "active_jobs": active_jobs,
        "recent_jobs": recent_jobs,
    }


class ScanJobListView(LoginRequiredMixin, ListView):
    model = ScanJob
    template_name = "scanners/list.html"
    context_object_name = "scan_jobs"
    paginate_by = 20

    def get_queryset(self):
        return get_scan_jobs_queryset()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["profiles"] = ScanProfile.objects.order_by("name")
        context["installer_script"] = generate_installer_script()
        context["queue_form"] = kwargs.get("queue_form", build_queue_form())
        context.update(get_live_monitor_context())
        return context


class ScanJobTableView(LoginRequiredMixin, TemplateView):
    template_name = "scanners/_jobs_table.html"

    def get(self, request, *args, **kwargs):
        scan_jobs = get_scan_jobs_queryset(limit=20)
        return render(request, self.template_name, {"scan_jobs": scan_jobs})


class ScanJobDetailView(LoginRequiredMixin, View):
    def get(self, request, pk, *args, **kwargs):
        job = get_object_or_404(ScanJob.objects.select_related("server", "application", "scan_profile"), pk=pk)
        context = get_job_detail_context(job)
        if request.headers.get("HX-Request"):
            return render(request, "scanners/_job_detail_panel.html", context)
        return render(request, "scanners/detail.html", context)


class ScanJobArtifactDownloadView(LoginRequiredMixin, View):
    def get(self, request, pk, filename, *args, **kwargs):
        job = get_object_or_404(ScanJob, pk=pk)
        output_dir = get_job_output_directory(job)
        if not output_dir:
            raise Http404("No artifacts available for this job.")

        artifact_path = (output_dir / filename).resolve()
        if artifact_path.parent != output_dir or not artifact_path.exists() or not artifact_path.is_file():
            raise Http404("Artifact not found.")

        content_type = guess_type(artifact_path.name)[0] or "application/octet-stream"
        return FileResponse(artifact_path.open("rb"), as_attachment=True, filename=artifact_path.name, content_type=content_type)


class LiveMonitorView(LoginRequiredMixin, TemplateView):
    template_name = "scanners/_live_updates.html"

    def get(self, request, *args, **kwargs):
        return render(request, self.template_name, get_live_monitor_context())


class ScanProfileWorkspaceMixin:
    template_name = "scanners/_profile_form_panel.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["profiles"] = ScanProfile.objects.order_by("name")
        return context

    def form_invalid(self, form):
        response = render(self.request, self.template_name, self.get_context_data(form=form, object=getattr(self, "object", None)))
        response.status_code = 422
        return response

    def form_valid(self, form):
        self.object = form.save()
        if form.cleaned_data.get("is_default"):
            ScanProfile.objects.exclude(pk=self.object.pk).update(is_default=False)
        messages.success(self.request, "Scan profile saved successfully.")
        if self.request.headers.get("HX-Request"):
            return render(
                self.request,
                "scanners/_profile_save_response.html",
                {
                    "profiles": ScanProfile.objects.order_by("name"),
                    "profile": self.object,
                },
            )
        return super().form_valid(form)


class ScanProfileCreateView(LoginRequiredMixin, ScanProfileWorkspaceMixin, CreateView):
    model = ScanProfile
    form_class = ScanProfileForm
    success_url = reverse_lazy("scanners:list")


class ScanProfileUpdateView(LoginRequiredMixin, ScanProfileWorkspaceMixin, UpdateView):
    model = ScanProfile
    form_class = ScanProfileForm
    success_url = reverse_lazy("scanners:list")


class QueueScanJobView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        form = QueueScanJobForm(request.POST)
        if not form.is_valid():
            response = render(request, "scanners/_queue_panel.html", {"queue_form": form})
            response.status_code = 422
            return response

        job = enqueue_scan_job(
            server=form.cleaned_data["server"],
            application=form.cleaned_data.get("application"),
            scan_profile=form.cleaned_data.get("scan_profile"),
            queue_name=ScanJob.Queue.SCAN,
            user=request.user,
        )
        return render(
            request,
            "scanners/_queue_response.html",
            {
                "message": f"Queued scan job #{job.pk} for {job.server.name}.",
                "queue_form": build_queue_form(),
                "scan_jobs": get_scan_jobs_queryset(limit=20),
                **get_live_monitor_context(),
            },
        )


class QueueServerJobView(LoginRequiredMixin, View):
    queue_map = {
        "install": ScanJob.Queue.INSTALL,
        "discovery": ScanJob.Queue.DISCOVERY,
    }

    def post(self, request, server_id, queue_name, *args, **kwargs):
        if queue_name not in self.queue_map:
            raise Http404("Unsupported queue action.")
        server = get_object_or_404(Server, pk=server_id)
        job = enqueue_scan_job(server=server, queue_name=self.queue_map[queue_name], user=request.user)
        return render(
            request,
            "scanners/_job_feedback.html",
            {"message": f"Queued {queue_name} job #{job.pk} for {server.name}.", **get_live_monitor_context()},
        )


class QuickQueueScanView(LoginRequiredMixin, View):
    def post(self, request, target_type, target_id, *args, **kwargs):
        default_profile = ScanProfile.objects.filter(is_default=True).first()
        initial = {}

        if target_type == "server":
            server = get_object_or_404(Server, pk=target_id)
            job = enqueue_scan_job(
                server=server,
                queue_name=ScanJob.Queue.SCAN,
                user=request.user,
                scan_profile=default_profile,
            )
            initial = {"server": server.pk, "scan_profile": getattr(default_profile, "pk", None)}
            message = f"Queued one-off server scan #{job.pk} for {server.name}."
        elif target_type == "application":
            application = get_object_or_404(Application.objects.select_related("server"), pk=target_id)
            job = enqueue_scan_job(
                server=application.server,
                application=application,
                queue_name=ScanJob.Queue.SCAN,
                user=request.user,
                scan_profile=default_profile,
            )
            initial = {
                "server": application.server.pk,
                "application": application.pk,
                "scan_profile": getattr(default_profile, "pk", None),
            }
            message = f"Queued one-off application scan #{job.pk} for {application.name}."
        else:
            raise Http404("Unsupported quick scan target.")

        return render_action_response(request, message, queue_form=build_queue_form(initial=initial))


class CancelScanJobView(LoginRequiredMixin, View):
    def post(self, request, pk, *args, **kwargs):
        job = get_object_or_404(ScanJob, pk=pk)
        if job.status in {ScanJob.Status.COMPLETED, ScanJob.Status.FAILED, ScanJob.Status.CANCELLED}:
            return render_action_response(request, f"Job #{job.pk} is already finished.")

        if job.status == ScanJob.Status.QUEUED:
            job.cancellation_requested = True
            job.save(update_fields=["cancellation_requested", "updated_at"])
            update_job_progress(
                job,
                stage=ScanJob.Stage.CANCELLED,
                status=ScanJob.Status.CANCELLED,
                ended_at=timezone.now(),
                message="Job cancelled before execution.",
                error_logs=job.error_logs or "Job cancelled before execution.",
            )
            return render_action_response(request, f"Cancelled queued job #{job.pk}.")

        job.cancellation_requested = True
        job.save(update_fields=["cancellation_requested", "updated_at"])
        update_job_progress(job, stage=ScanJob.Stage.CANCEL_REQUESTED, message="Cancellation requested by user.")
        return render_action_response(request, f"Cancellation requested for job #{job.pk}.")


class RetryScanJobView(LoginRequiredMixin, View):
    def post(self, request, pk, *args, **kwargs):
        job = get_object_or_404(ScanJob.objects.select_related("server", "application", "scan_profile"), pk=pk)
        if job.status not in {ScanJob.Status.FAILED, ScanJob.Status.CANCELLED, ScanJob.Status.COMPLETED_WITH_WARNINGS}:
            return render_action_response(request, f"Job #{job.pk} is not retryable.")

        retry_job = enqueue_scan_job(
            server=job.server,
            application=job.application,
            scan_profile=job.scan_profile,
            queue_name=job.queue_name,
            user=request.user,
        )
        return render_action_response(request, f"Queued retry job #{retry_job.pk} from job #{job.pk}.")


class QueueScheduledScansView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        queued_jobs = queue_scheduled_scans(reference_time=timezone.now())
        if not queued_jobs:
            return render_action_response(request, "No scheduled scans were due. Make sure the server is installed and the profile schedule is not Manual.")
        return render_action_response(request, f"Queued {len(queued_jobs)} scheduled scan job(s).")


class InstallerScriptView(LoginRequiredMixin, TemplateView):
    def get(self, request, *args, **kwargs):
        return HttpResponse(generate_installer_script(), content_type="text/plain")
