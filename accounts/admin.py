from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as DjangoUserAdmin

from .models import Organization, User


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
	list_display = ("name", "slug", "created_at")
	search_fields = ("name", "slug")


@admin.register(User)
class UserAdmin(DjangoUserAdmin):
	ordering = ("email",)
	list_display = ("email", "full_name", "role", "organization", "is_staff", "is_active")
	search_fields = ("email", "full_name")

	fieldsets = (
		(None, {"fields": ("email", "password")}),
		("Profile", {"fields": ("full_name", "organization", "role")}),
		(
			"Permissions",
			{
				"fields": (
					"is_active",
					"is_staff",
					"is_superuser",
					"groups",
					"user_permissions",
				)
			},
		),
		("Important dates", {"fields": ("last_login", "date_joined")}),
	)

	add_fieldsets = (
		(
			None,
			{
				"classes": ("wide",),
				"fields": ("email", "full_name", "password1", "password2", "role", "is_staff", "is_superuser"),
			},
		),
	)
