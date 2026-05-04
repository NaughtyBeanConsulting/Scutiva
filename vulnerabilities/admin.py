from django.contrib import admin

from .models import VulnerabilityFinding


@admin.register(VulnerabilityFinding)
class VulnerabilityFindingAdmin(admin.ModelAdmin):
	list_display = ("cve_id", "severity", "package_name", "server", "source_scanner", "fix_available", "status", "last_seen")
	list_filter = ("severity", "status", "source_scanner", "fix_available", "cisa_kev", "exploit_known")
	search_fields = ("cve_id", "package_name", "affected_path", "server__name")
