from django import forms

from core.forms import StyledFormMixin

from .models import Server


class ServerForm(StyledFormMixin, forms.ModelForm):
    password = forms.CharField(required=False, widget=forms.PasswordInput(render_value=True))
    private_key = forms.CharField(required=False, widget=forms.Textarea)
    sudo_password = forms.CharField(required=False, widget=forms.PasswordInput(render_value=True))
    host_key_algorithm = forms.CharField(required=False, widget=forms.HiddenInput())
    host_key_fingerprint = forms.CharField(required=False, widget=forms.HiddenInput())
    verified_host = forms.CharField(required=False, widget=forms.HiddenInput())
    verified_ssh_port = forms.CharField(required=False, widget=forms.HiddenInput())

    class Meta:
        model = Server
        fields = [
            "name",
            "host",
            "ssh_port",
            "username",
            "authentication_type",
            "environment",
            "codebase_paths",
            "tags",
            "description",
            "is_active",
        ]

    def clean(self):
        cleaned_data = super().clean()
        auth_type = cleaned_data.get("authentication_type")
        password = cleaned_data.get("password")
        private_key = cleaned_data.get("private_key")
        host = str(cleaned_data.get("host") or "").strip()
        ssh_port = str(cleaned_data.get("ssh_port") or "").strip()
        verified_host = str(cleaned_data.get("verified_host") or "").strip()
        verified_ssh_port = str(cleaned_data.get("verified_ssh_port") or "").strip()
        fingerprint = str(cleaned_data.get("host_key_fingerprint") or "").strip()
        algorithm = str(cleaned_data.get("host_key_algorithm") or "").strip()

        if auth_type == Server.AuthenticationType.PASSWORD and not password:
            self.add_error("password", "Password authentication requires a password.")

        if auth_type == Server.AuthenticationType.PRIVATE_KEY and not private_key:
            self.add_error("private_key", "Private key authentication requires a private key.")

        if fingerprint and (verified_host != host or verified_ssh_port != ssh_port):
            fingerprint = ""
            algorithm = ""

        if not fingerprint and self.instance.pk:
            same_target = self.instance.host == host and str(self.instance.ssh_port) == ssh_port
            if same_target:
                fingerprint = self.instance.host_key_fingerprint
                algorithm = self.instance.host_key_algorithm

        if cleaned_data.get("environment") == Server.Environment.PRODUCTION and not fingerprint:
            self.add_error(None, "Production servers require a verified SSH host fingerprint. Use Test SSH connection before saving.")

        cleaned_data["host_key_fingerprint"] = fingerprint
        cleaned_data["host_key_algorithm"] = algorithm if fingerprint else ""

        return cleaned_data

    def save(self, commit=True):
        server = super().save(commit=False)

        if self.cleaned_data.get("password"):
            server.set_password(self.cleaned_data["password"])
        if self.cleaned_data.get("private_key"):
            server.set_private_key(self.cleaned_data["private_key"])
        if self.cleaned_data.get("sudo_password"):
            server.set_sudo_password(self.cleaned_data["sudo_password"])
        server.host_key_fingerprint = self.cleaned_data.get("host_key_fingerprint", "")
        server.host_key_algorithm = self.cleaned_data.get("host_key_algorithm", "")

        if commit:
            server.save()
        return server