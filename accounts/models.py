from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone

from .managers import UserManager


class Organization(models.Model):
	name = models.CharField(max_length=255, unique=True)
	slug = models.SlugField(max_length=255, unique=True)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ["name"]

	def __str__(self):
		return self.name


class User(AbstractUser):
	class Role(models.TextChoices):
		ADMIN = "admin", "Admin"
		SECURITY_ANALYST = "security_analyst", "Security Analyst"
		DEVELOPER = "developer", "Developer"
		VIEWER = "viewer", "Viewer"

	username = None
	email = models.EmailField(unique=True)
	full_name = models.CharField(max_length=255)
	organization = models.ForeignKey(
		Organization,
		on_delete=models.SET_NULL,
		related_name="users",
		null=True,
		blank=True,
	)
	role = models.CharField(max_length=32, choices=Role.choices, default=Role.VIEWER)
	date_joined = models.DateTimeField(default=timezone.now)

	USERNAME_FIELD = "email"
	REQUIRED_FIELDS = ["full_name"]

	objects = UserManager()

	class Meta:
		ordering = ["email"]

	def __str__(self):
		return self.email
