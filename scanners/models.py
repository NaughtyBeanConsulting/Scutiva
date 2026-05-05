from django.db import models, transaction
from django.utils import timezone

from core.models import TimeStampedModel


class ScanProfile(TimeStampedModel):
    class Schedule(models.TextChoices):
        MANUAL = "manual", "Manual only"
        DAILY = "daily", "Daily"
        WEEKLY = "weekly", "Weekly"
        MONTHLY = "monthly", "Monthly"

    class SeverityThreshold(models.TextChoices):
        UNKNOWN = "unknown", "Unknown"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    scan_os_packages = models.BooleanField(default=True)
    scan_application_directories = models.BooleanField(default=True)
    scan_docker_images = models.BooleanField(default=False)
    scan_containers = models.BooleanField(default=False)
    scan_dependency_manifests = models.BooleanField(default=True)
    scan_iac_files = models.BooleanField(default=True)
    scan_shell_scripts = models.BooleanField(default=True)
    enable_syft = models.BooleanField(default=True)
    enable_grype = models.BooleanField(default=True)
    enable_trivy = models.BooleanField(default=True)
    enable_lynis = models.BooleanField(default=True)
    include_dev_dependencies = models.BooleanField(default=False)
    severity_threshold = models.CharField(max_length=16, choices=SeverityThreshold.choices, default=SeverityThreshold.MEDIUM)
    include_paths = models.TextField(blank=True)
    exclude_paths = models.TextField(blank=True)
    schedule = models.CharField(max_length=16, choices=Schedule.choices, default=Schedule.MANUAL)
    is_default = models.BooleanField(default=False)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name


class ScannerInstallation(TimeStampedModel):
    class Status(models.TextChoices):
        NOT_INSTALLED = "not_installed", "Not installed"
        INSTALLING = "installing", "Installing"
        INSTALLED = "installed", "Installed"
        FAILED = "failed", "Failed"

    server = models.OneToOneField("servers.Server", on_delete=models.CASCADE, related_name="scanner_installation")
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.NOT_INSTALLED)
    syft_version = models.CharField(max_length=64, blank=True)
    grype_version = models.CharField(max_length=64, blank=True)
    trivy_version = models.CharField(max_length=64, blank=True)
    lynis_version = models.CharField(max_length=64, blank=True)
    last_install_date = models.DateTimeField(null=True, blank=True)
    install_logs = models.TextField(blank=True)

    def __str__(self):
        return f"{self.server.name} scanner tools"


class ScanJobManager(models.Manager):
    def claim_next(self, queue_name=None):
        with transaction.atomic():
            queryset = self.select_for_update(skip_locked=True).filter(
                status=ScanJob.Status.QUEUED,
                cancellation_requested=False,
            )
            if queue_name:
                queryset = queryset.filter(queue_name=queue_name)

            job = queryset.order_by("created_at").first()
            if not job:
                return None

            now = timezone.now()
            job.status = ScanJob.Status.PROCESSING
            job.stage = ScanJob.Stage.CLAIMED
            job.progress_percent = 5
            job.current_command = ""
            job.claimed_at = now
            job.started_at = now
            job.attempts += 1
            job.save(update_fields=["status", "stage", "progress_percent", "current_command", "claimed_at", "started_at", "attempts", "updated_at"])
            return job


class ScanJob(TimeStampedModel):
    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        PROCESSING = "processing", "Processing"
        COMPLETED = "completed", "Completed"
        COMPLETED_WITH_WARNINGS = "completed_with_warnings", "Completed with warnings"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    class Queue(models.TextChoices):
        DEFAULT = "default", "Default"
        INSTALL = "install", "Tool installation"
        DISCOVERY = "discovery", "Application discovery"
        SCAN = "scan", "Scan execution"

    class Stage(models.TextChoices):
        QUEUED = "queued", "Queued"
        CLAIMED = "claimed", "Claimed by worker"
        INSTALLING_TOOLS = "installing_tools", "Installing tools"
        DISCOVERING_APPS = "discovering_apps", "Discovering apps"
        PREPARING_TARGET = "preparing_target", "Preparing target"
        BUILDING_SBOM = "building_sbom", "Building SBOM"
        RUNNING_GRYPE = "running_grype", "Running Grype"
        RUNNING_TRIVY = "running_trivy", "Running Trivy"
        RUNNING_LYNIS = "running_lynis", "Running Lynis"
        PARSING_RESULTS = "parsing_results", "Parsing results"
        COMPLETED = "completed", "Completed"
        CANCEL_REQUESTED = "cancel_requested", "Cancel requested"
        CANCELLED = "cancelled", "Cancelled"
        FAILED = "failed", "Failed"

    server = models.ForeignKey("servers.Server", on_delete=models.CASCADE, related_name="scan_jobs")
    application = models.ForeignKey("servers.Application", on_delete=models.SET_NULL, related_name="scan_jobs", null=True, blank=True)
    scan_profile = models.ForeignKey(ScanProfile, on_delete=models.SET_NULL, related_name="scan_jobs", null=True, blank=True)
    queue_name = models.CharField(max_length=32, choices=Queue.choices, default=Queue.SCAN)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.QUEUED)
    stage = models.CharField(max_length=32, choices=Stage.choices, default=Stage.QUEUED)
    progress_percent = models.PositiveSmallIntegerField(default=0)
    current_command = models.CharField(max_length=500, blank=True)
    progress_context = models.JSONField(default=dict, blank=True)
    tools_used = models.JSONField(default=list, blank=True)
    raw_output_path = models.CharField(max_length=500, blank=True)
    parsed_findings = models.JSONField(default=list, blank=True)
    error_logs = models.TextField(blank=True)
    claimed_at = models.DateTimeField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    ended_at = models.DateTimeField(null=True, blank=True)
    attempts = models.PositiveIntegerField(default=0)
    cancellation_requested = models.BooleanField(default=False)

    objects = ScanJobManager()

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Scan {self.pk} on {self.server.name}"


class ComplianceFinding(TimeStampedModel):
    class Severity(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"
        INFO = "info", "Info"
        UNKNOWN = "unknown", "Unknown"

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        ACCEPTED_RISK = "accepted_risk", "Accepted risk"
        FALSE_POSITIVE = "false_positive", "False positive"
        FIXED = "fixed", "Fixed"
        IGNORED = "ignored", "Ignored"

    source_scanner = models.CharField(max_length=32)
    benchmark = models.CharField(max_length=255, blank=True)
    control_id = models.CharField(max_length=255, db_index=True)
    title = models.CharField(max_length=500)
    severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.UNKNOWN)
    resource = models.CharField(max_length=500, blank=True)
    application = models.ForeignKey("servers.Application", on_delete=models.SET_NULL, related_name="compliance_findings", null=True, blank=True)
    server = models.ForeignKey("servers.Server", on_delete=models.CASCADE, related_name="compliance_findings")
    scan_job = models.ForeignKey("scanners.ScanJob", on_delete=models.SET_NULL, related_name="compliance_findings", null=True, blank=True)
    description = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    references = models.JSONField(default=list, blank=True)
    first_seen = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    status = models.CharField(max_length=32, choices=Status.choices, default=Status.OPEN)
    raw_output = models.TextField(blank=True)

    class Meta:
        ordering = ["-last_seen", "-created_at"]

    def __str__(self):
        return f"{self.source_scanner}:{self.control_id}"


class ScheduledScanDispatch(TimeStampedModel):
    profile = models.ForeignKey(ScanProfile, on_delete=models.CASCADE, related_name="scheduled_dispatches")
    server = models.ForeignKey("servers.Server", on_delete=models.CASCADE, related_name="scheduled_dispatches")
    window_start = models.DateTimeField()
    window_end = models.DateTimeField()
    scan_job = models.OneToOneField("scanners.ScanJob", on_delete=models.SET_NULL, related_name="scheduled_dispatch", null=True, blank=True)

    class Meta:
        ordering = ["-window_start", "server__name"]
        unique_together = ("profile", "server", "window_start", "window_end")

    def __str__(self):
        return f"{self.profile.name} -> {self.server.name} ({self.window_start:%Y-%m-%d})"
