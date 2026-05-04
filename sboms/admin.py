from django.contrib import admin

from .models import SBOMArtifact


@admin.register(SBOMArtifact)
class SBOMArtifactAdmin(admin.ModelAdmin):
	list_display = ("id", "server", "application", "generated_by", "format", "package_count", "created_date")
	list_filter = ("generated_by", "format")
