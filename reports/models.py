from django.conf import settings
from django.db import models

from core.models import TimeStampedModel


class ReportArtifact(TimeStampedModel):
	class ReportType(models.TextChoices):
		EXECUTIVE = "executive", "Executive summary"
		SERVER = "server", "Server vulnerabilities"
		APPLICATION = "application", "Application vulnerabilities"
		CRITICAL = "critical", "Critical CVEs"
		KEV = "kev", "CISA KEV"
		FIX_AVAILABLE = "fix_available", "Fix available"
		OPEN = "open", "Open vulnerabilities"

	class OutputFormat(models.TextChoices):
		HTML = "html", "HTML"
		JSON = "json", "JSON"
		CSV = "csv", "CSV"
		PDF = "pdf", "PDF"

	name = models.CharField(max_length=255)
	report_type = models.CharField(max_length=32, choices=ReportType.choices)
	output_format = models.CharField(max_length=16, choices=OutputFormat.choices)
	filters = models.JSONField(default=dict, blank=True)
	file_path = models.CharField(max_length=500, blank=True)
	generated_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, related_name="reports", null=True, blank=True)

	class Meta:
		ordering = ["-created_at"]

	def __str__(self):
		return self.name
