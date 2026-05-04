from contextlib import contextmanager
from dataclasses import dataclass
from io import StringIO
import shlex

import paramiko
from django.utils import timezone

from .models import Server


@dataclass
class SSHCommandResult:
    command: str
    stdout: str
    stderr: str
    exit_status: int


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
        "timeout": 15,
        "banner_timeout": 15,
        "auth_timeout": 15,
    }

    if data["authentication_type"] == Server.AuthenticationType.PASSWORD:
        connect_kwargs["password"] = data.get("password")
    else:
        connect_kwargs["pkey"] = _load_private_key(data.get("private_key"))

    return connect_kwargs


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


@contextmanager
def ssh_client_for_server(server):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(**_build_connect_kwargs(_server_connection_data(server)))
        _mark_server_status(server, True)
        yield client
    except Exception:
        _mark_server_status(server, False)
        raise
    finally:
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
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(**_build_connect_kwargs(cleaned_data))
        return True, "SSH connection succeeded."
    except Exception as exc:
        return False, str(exc)
    finally:
        client.close()