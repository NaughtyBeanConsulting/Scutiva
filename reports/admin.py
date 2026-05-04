from django.contrib import admin

from .models import ReportArtifact


@admin.register(ReportArtifact)
class ReportArtifactAdmin(admin.ModelAdmin):
	list_display = ("name", "report_type", "output_format", "generated_by", "created_at")
	list_filter = ("report_type", "output_format")
