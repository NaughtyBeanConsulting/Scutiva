from django.contrib import admin

from .models import Application, Server


@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
	list_display = ("name", "host", "environment", "authentication_type", "last_connection_status", "is_active")
	list_filter = ("environment", "authentication_type", "last_connection_status", "is_active")
	search_fields = ("name", "host", "username", "tags")


@admin.register(Application)
class ApplicationAdmin(admin.ModelAdmin):
	list_display = ("name", "server", "language", "framework", "package_manager")
	list_filter = ("language", "framework", "package_manager")
	search_fields = ("name", "path", "git_repository_url")
