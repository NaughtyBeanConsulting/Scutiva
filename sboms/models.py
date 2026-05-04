from django.db import models

from core.models import TimeStampedModel


class SBOMArtifact(TimeStampedModel):
	server = models.ForeignKey("servers.Server", on_delete=models.CASCADE, related_name="sboms")
	application = models.ForeignKey("servers.Application", on_delete=models.SET_NULL, related_name="sboms", null=True, blank=True)
	generated_by = models.CharField(max_length=64, default="syft")
	format = models.CharField(max_length=32, default="json")
	file_path = models.CharField(max_length=500)
	created_date = models.DateTimeField(auto_now_add=True)
	package_count = models.PositiveIntegerField(default=0)
	related_scan = models.ForeignKey("scanners.ScanJob", on_delete=models.SET_NULL, related_name="sboms", null=True, blank=True)

	class Meta:
		ordering = ["-created_date"]

	def __str__(self):
		return f"SBOM {self.pk} for {self.server.name}"
