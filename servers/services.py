from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from io import StringIO
import shlex
import time
from base64 import urlsafe_b64encode

import paramiko
from django.conf import settings
from django.utils import timezone

from .models import Server


@dataclass
class SSHCommandResult:
    command: str
    stdout: str
    stderr: str
    exit_status: int


class ExpectedHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    def __init__(self, *, expected_fingerprint="", allow_auto_add=False):
        self.expected_fingerprint = (expected_fingerprint or "").strip()
        self.allow_auto_add = allow_auto_add

    def missing_host_key(self, client, hostname, key):
        actual_fingerprint = format_host_key_fingerprint(key)
        if self.expected_fingerprint:
            if actual_fingerprint != self.expected_fingerprint:
                raise paramiko.SSHException(
                    f"Host key fingerprint mismatch for {hostname}. Expected {self.expected_fingerprint}, got {actual_fingerprint}."
                )
            client.get_host_keys().add(hostname, key.get_name(), key)
            return

        if not self.allow_auto_add:
            raise paramiko.SSHException(
                f"Host key for {hostname} is not pinned. Capture and save the fingerprint before connecting."
            )

        client.get_host_keys().add(hostname, key.get_name(), key)


def _load_private_key(private_key_text):
    if not private_key_text:
        return None

    key_buffer = StringIO(private_key_text)
    for key_cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
        key_buffer.seek(0)
        try:
            return key_cls.from_private_key(key_buffer)
        except paramiko.SSHException:
            continue
    raise paramiko.SSHException("Unsupported private key format.")


def _build_connect_kwargs(data):
    connect_kwargs = {
        "hostname": data["host"],
        "port": data["ssh_port"],
        "username": data["username"],
        "timeout": settings.SSH_CONNECT_TIMEOUT,
        "banner_timeout": settings.SSH_BANNER_TIMEOUT,
        "auth_timeout": settings.SSH_AUTH_TIMEOUT,
    }

    if data["authentication_type"] == Server.AuthenticationType.PASSWORD:
        connect_kwargs["password"] = data.get("password")
    else:
        connect_kwargs["pkey"] = _load_private_key(data.get("private_key"))

    return connect_kwargs


def format_host_key_fingerprint(key):
    digest = sha256(key.asbytes()).digest()
    encoded = urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"SHA256:{encoded}"


def _expected_fingerprint_from_data(data):
    expected_fingerprint = str(data.get("host_key_fingerprint") or "").strip()
    verified_host = str(data.get("verified_host") or "").strip()
    verified_ssh_port = str(data.get("verified_ssh_port") or "").strip()
    current_host = str(data.get("host") or "").strip()
    current_port = str(data.get("ssh_port") or "").strip()

    if expected_fingerprint and verified_host == current_host and verified_ssh_port == current_port:
        return expected_fingerprint
    return ""


def _server_connection_data(server):
    return {
        "host": server.host,
        "ssh_port": server.ssh_port,
        "username": server.username,
        "authentication_type": server.authentication_type,
        "password": server.get_password(),
        "private_key": server.get_private_key(),
    }


def _mark_server_status(server, ok):
    server.last_connection_status = (
        Server.ConnectionStatus.SUCCESS if ok else Server.ConnectionStatus.FAILED
    )
    if ok:
        server.last_successful_connection_at = timezone.now()
    server.save(update_fields=["last_connection_status", "last_successful_connection_at", "updated_at"])


def _build_host_key_policy(*, expected_fingerprint="", allow_auto_add=False):
    return ExpectedHostKeyPolicy(expected_fingerprint=expected_fingerprint, allow_auto_add=allow_auto_add)


def _connect_client(connect_kwargs, *, expected_fingerprint="", allow_auto_add=False):
    last_error = None
    attempts = max(1, settings.SSH_CONNECT_RETRIES)

    for attempt in range(1, attempts + 1):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(_build_host_key_policy(expected_fingerprint=expected_fingerprint, allow_auto_add=allow_auto_add))
        try:
            client.connect(**connect_kwargs)
            return client
        except (paramiko.SSHException, OSError) as exc:
            client.close()
            last_error = exc
            if attempt >= attempts:
                raise
            time.sleep(settings.SSH_RETRY_DELAY_SECONDS)

    raise last_error


@contextmanager
def ssh_client_for_server(server):
    client = None
    try:
        expected_fingerprint = (server.host_key_fingerprint or "").strip()
        if server.requires_pinned_host_key() and not expected_fingerprint:
            raise ValueError("Production servers require a pinned SSH host fingerprint.")

        client = _connect_client(
            _build_connect_kwargs(_server_connection_data(server)),
            expected_fingerprint=expected_fingerprint,
            allow_auto_add=not expected_fingerprint and settings.SSH_AUTO_ADD_HOST_KEYS and not server.requires_pinned_host_key(),
        )
        _mark_server_status(server, True)
        yield client
    except Exception:
        _mark_server_status(server, False)
        raise
    finally:
        if client is not None:
            client.close()


def run_remote_command(server, command, sudo=False, timeout=1200):
    with ssh_client_for_server(server) as client:
        if sudo:
            sudo_password = server.get_sudo_password() or server.get_password()
            if not sudo_password:
                raise ValueError("Sudo password is required for this operation.")
            escaped_command = shlex.quote(command)
            remote_command = f"sudo -S bash -lc {escaped_command}"
        else:
            remote_command = f"bash -lc {shlex.quote(command)}"

        stdin, stdout, stderr = client.exec_command(remote_command, get_pty=True, timeout=timeout)
        if sudo:
            stdin.write((server.get_sudo_password() or server.get_password()) + "\n")
            stdin.flush()
        stdout_text = stdout.read().decode("utf-8", errors="replace")
        stderr_text = stderr.read().decode("utf-8", errors="replace")
        exit_status = stdout.channel.recv_exit_status()
        return SSHCommandResult(
            command=remote_command,
            stdout=stdout_text,
            stderr=stderr_text,
            exit_status=exit_status,
        )


def upload_text(server, content, remote_path, mode=0o600):
    with ssh_client_for_server(server) as client:
        with client.open_sftp() as sftp:
            with sftp.file(remote_path, "w") as remote_file:
                remote_file.write(content)
            sftp.chmod(remote_path, mode)


def download_text(server, remote_path):
    with ssh_client_for_server(server) as client:
        with client.open_sftp() as sftp:
            with sftp.file(remote_path, "r") as remote_file:
                return remote_file.read().decode("utf-8", errors="replace")


def test_ssh_connection(cleaned_data):
    try:
        expected_fingerprint = _expected_fingerprint_from_data(cleaned_data)
        environment = cleaned_data.get("environment")
        requires_pinned = environment == Server.Environment.PRODUCTION
        client = _connect_client(
            _build_connect_kwargs(cleaned_data),
            expected_fingerprint=expected_fingerprint,
            allow_auto_add=not expected_fingerprint and not requires_pinned,
        )
        remote_key = client.get_transport().get_remote_server_key()
        fingerprint = format_host_key_fingerprint(remote_key)
        algorithm = remote_key.get_name()
        return True, f"SSH connection succeeded. Captured {algorithm} fingerprint {fingerprint}.", {
            "host_key_algorithm": algorithm,
            "host_key_fingerprint": fingerprint,
            "verified_host": str(cleaned_data.get("host") or "").strip(),
            "verified_ssh_port": str(cleaned_data.get("ssh_port") or "").strip(),
        }
    except Exception as exc:
        return False, str(exc), {}
    finally:
        if "client" in locals():
            client.close()