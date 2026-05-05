from django.contrib import admin

from .models import ComplianceFinding, ScanJob, ScanProfile, ScannerInstallation, ScheduledScanDispatch


@admin.register(ScanProfile)
class ScanProfileAdmin(admin.ModelAdmin):
	list_display = ("name", "schedule", "severity_threshold", "enable_syft", "enable_grype", "enable_trivy", "enable_lynis", "is_default")
	list_filter = ("schedule", "severity_threshold", "enable_syft", "enable_grype", "enable_trivy", "enable_lynis", "is_default")


@admin.register(ScannerInstallation)
class ScannerInstallationAdmin(admin.ModelAdmin):
	list_display = ("server", "status", "syft_version", "grype_version", "trivy_version", "lynis_version", "last_install_date")
	list_filter = ("status",)


@admin.register(ScanJob)
class ScanJobAdmin(admin.ModelAdmin):
	list_display = ("id", "server", "application", "scan_profile", "status", "started_at", "ended_at")
	list_filter = ("status",)
	search_fields = ("server__name", "application__name", "raw_output_path")


@admin.register(ComplianceFinding)
class ComplianceFindingAdmin(admin.ModelAdmin):
	list_display = ("control_id", "source_scanner", "severity", "server", "application", "status", "last_seen")
	list_filter = ("source_scanner", "severity", "status")
	search_fields = ("control_id", "title", "server__name", "application__name", "benchmark")


@admin.register(ScheduledScanDispatch)
class ScheduledScanDispatchAdmin(admin.ModelAdmin):
	list_display = ("profile", "server", "window_start", "window_end", "scan_job")
	list_filter = ("profile",)
	search_fields = ("profile__name", "server__name")
