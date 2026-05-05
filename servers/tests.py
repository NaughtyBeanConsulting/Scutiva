import paramiko
from django.test import TestCase, override_settings

from .forms import ServerForm
from .models import Server
from .services import ExpectedHostKeyPolicy, format_host_key_fingerprint


class ServerFormTests(TestCase):
	def test_production_server_requires_verified_host_key(self):
		form = ServerForm(
			data={
				"name": "Prod VM",
				"host": "prod.example.com",
				"ssh_port": 22,
				"username": "ubuntu",
				"authentication_type": Server.AuthenticationType.PASSWORD,
				"environment": Server.Environment.PRODUCTION,
				"codebase_paths": "/var/www",
				"is_active": True,
				"password": "secret",
			}
		)

		self.assertFalse(form.is_valid())
		self.assertIn("verified SSH host fingerprint", form.non_field_errors()[0])

	def test_production_server_accepts_matching_verified_host_key(self):
		form = ServerForm(
			data={
				"name": "Prod VM",
				"host": "prod.example.com",
				"ssh_port": 22,
				"username": "ubuntu",
				"authentication_type": Server.AuthenticationType.PASSWORD,
				"environment": Server.Environment.PRODUCTION,
				"codebase_paths": "/var/www",
				"is_active": True,
				"password": "secret",
				"host_key_algorithm": "ssh-ed25519",
				"host_key_fingerprint": "SHA256:testfingerprint",
				"verified_host": "prod.example.com",
				"verified_ssh_port": "22",
			}
		)

		self.assertTrue(form.is_valid(), form.errors)
		server = form.save(commit=False)
		self.assertEqual(server.host_key_fingerprint, "SHA256:testfingerprint")


class HostKeyPolicyTests(TestCase):
	@override_settings(SSH_AUTO_ADD_HOST_KEYS=False)
	def test_expected_host_key_policy_accepts_matching_fingerprint(self):
		key = paramiko.RSAKey.generate(1024)
		policy = ExpectedHostKeyPolicy(expected_fingerprint=format_host_key_fingerprint(key), allow_auto_add=False)

		class DummyClient:
			def __init__(self):
				self.host_keys = paramiko.HostKeys()

			def get_host_keys(self):
				return self.host_keys

		client = DummyClient()
		policy.missing_host_key(client, "prod.example.com", key)

		self.assertIn("prod.example.com", client.host_keys)

	def test_expected_host_key_policy_rejects_mismatch(self):
		key = paramiko.RSAKey.generate(1024)
		wrong_key = paramiko.RSAKey.generate(1024)
		policy = ExpectedHostKeyPolicy(expected_fingerprint=format_host_key_fingerprint(wrong_key), allow_auto_add=False)

		class DummyClient:
			def __init__(self):
				self.host_keys = paramiko.HostKeys()

			def get_host_keys(self):
				return self.host_keys

		with self.assertRaises(paramiko.SSHException):
			policy.missing_host_key(DummyClient(), "prod.example.com", key)
