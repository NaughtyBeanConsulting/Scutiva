from django.conf import settings
from django.db import models
from django.utils import timezone

from core.models import TimeStampedModel
from core.security import decrypt_value, encrypt_value


class Server(TimeStampedModel):
	class AuthenticationType(models.TextChoices):
		PASSWORD = "password", "Password"
		PRIVATE_KEY = "private_key", "Private key"

	class Environment(models.TextChoices):
		PRODUCTION = "production", "Production"
		STAGING = "staging", "Staging"
		DEVELOPMENT = "development", "Development"
		TEST = "test", "Test"

	class ConnectionStatus(models.TextChoices):
		UNKNOWN = "unknown", "Unknown"
		SUCCESS = "success", "Success"
		FAILED = "failed", "Failed"

	name = models.CharField(max_length=255)
	host = models.CharField(max_length=255)
	ssh_port = models.PositiveIntegerField(default=22)
	username = models.CharField(max_length=255)
	authentication_type = models.CharField(max_length=32, choices=AuthenticationType.choices)
	encrypted_password = models.TextField(blank=True)
	encrypted_private_key = models.TextField(blank=True)
	encrypted_sudo_password = models.TextField(blank=True)
	environment = models.CharField(max_length=32, choices=Environment.choices, default=Environment.PRODUCTION)
	codebase_paths = models.TextField(
		blank=True,
		default="/var/www\n/srv/apps\n/opt/apps\n/home\n/app",
	)
	tags = models.CharField(max_length=255, blank=True)
	description = models.TextField(blank=True)
	is_active = models.BooleanField(default=True)
	host_key_algorithm = models.CharField(max_length=64, blank=True)
	host_key_fingerprint = models.CharField(max_length=255, blank=True)
	last_connection_status = models.CharField(max_length=32, choices=ConnectionStatus.choices, default=ConnectionStatus.UNKNOWN)
	last_successful_connection_at = models.DateTimeField(null=True, blank=True)
	credential_updated_at = models.DateTimeField(null=True, blank=True)
	created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name="servers")

	class Meta:
		ordering = ["name"]

	def __str__(self):
		return self.name

	def set_password(self, value):
		self.encrypted_password = encrypt_value(value)
		self.credential_updated_at = timezone.now()

	def get_password(self):
		return decrypt_value(self.encrypted_password)

	def set_private_key(self, value):
		self.encrypted_private_key = encrypt_value(value)
		self.credential_updated_at = timezone.now()

	def get_private_key(self):
		return decrypt_value(self.encrypted_private_key)

	def set_sudo_password(self, value):
		self.encrypted_sudo_password = encrypt_value(value)
		self.credential_updated_at = timezone.now()

	def get_sudo_password(self):
		return decrypt_value(self.encrypted_sudo_password)

	def get_codebase_paths(self):
		return [path.strip() for path in self.codebase_paths.splitlines() if path.strip()]

	def requires_pinned_host_key(self):
		return self.environment == self.Environment.PRODUCTION


class Application(TimeStampedModel):
	server = models.ForeignKey(Server, on_delete=models.CASCADE, related_name="applications")
	name = models.CharField(max_length=255)
	path = models.CharField(max_length=500)
	project_type = models.CharField(max_length=120, blank=True)
	framework = models.CharField(max_length=120, blank=True)
	language = models.CharField(max_length=120, blank=True)
	dependency_files = models.JSONField(default=list, blank=True)
	git_repository_url = models.URLField(blank=True)
	git_branch = models.CharField(max_length=255, blank=True)
	git_commit_hash = models.CharField(max_length=120, blank=True)
	package_manager = models.CharField(max_length=120, blank=True)
	dockerfile_present = models.BooleanField(default=False)
	docker_compose_present = models.BooleanField(default=False)
	last_discovered_at = models.DateTimeField(null=True, blank=True)

	class Meta:
		ordering = ["name", "path"]
		unique_together = ("server", "path")

	def __str__(self):
		return f"{self.server.name}: {self.name}"
