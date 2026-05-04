from django.db import models

from core.models import TimeStampedModel


class VulnerabilityFinding(TimeStampedModel):
	class Severity(models.TextChoices):
		CRITICAL = "critical", "Critical"
		HIGH = "high", "High"
		MEDIUM = "medium", "Medium"
		LOW = "low", "Low"
		UNKNOWN = "unknown", "Unknown"

	class Status(models.TextChoices):
		OPEN = "open", "Open"
		ACCEPTED_RISK = "accepted_risk", "Accepted risk"
		FALSE_POSITIVE = "false_positive", "False positive"
		FIXED = "fixed", "Fixed"
		IGNORED = "ignored", "Ignored"

	cve_id = models.CharField(max_length=64, db_index=True)
	source_scanner = models.CharField(max_length=32)
	severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.UNKNOWN)
	cvss_score = models.DecimalField(max_digits=4, decimal_places=1, null=True, blank=True)
	package_name = models.CharField(max_length=255)
	installed_version = models.CharField(max_length=255, blank=True)
	fixed_version = models.CharField(max_length=255, blank=True)
	package_type = models.CharField(max_length=120, blank=True)
	ecosystem = models.CharField(max_length=120, blank=True)
	affected_path = models.CharField(max_length=500, blank=True)
	application = models.ForeignKey("servers.Application", on_delete=models.SET_NULL, related_name="findings", null=True, blank=True)
	server = models.ForeignKey("servers.Server", on_delete=models.CASCADE, related_name="findings")
	scan_job = models.ForeignKey("scanners.ScanJob", on_delete=models.SET_NULL, related_name="findings", null=True, blank=True)
	description = models.TextField(blank=True)
	references = models.JSONField(default=list, blank=True)
	fix_available = models.BooleanField(default=False)
	exploit_known = models.BooleanField(default=False)
	cisa_kev = models.BooleanField(default=False)
	first_seen = models.DateTimeField(null=True, blank=True)
	last_seen = models.DateTimeField(null=True, blank=True)
	status = models.CharField(max_length=32, choices=Status.choices, default=Status.OPEN)
	remediation_notes = models.TextField(blank=True)
	raw_output = models.TextField(blank=True)

	class Meta:
		ordering = ["-last_seen", "-created_at"]

	def __str__(self):
		return self.cve_id
