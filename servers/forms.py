from django import forms

from core.forms import StyledFormMixin

from .models import Server


class ServerForm(StyledFormMixin, forms.ModelForm):
    password = forms.CharField(required=False, widget=forms.PasswordInput(render_value=True))
    private_key = forms.CharField(required=False, widget=forms.Textarea)
    sudo_password = forms.CharField(required=False, widget=forms.PasswordInput(render_value=True))

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

        if auth_type == Server.AuthenticationType.PASSWORD and not password:
            self.add_error("password", "Password authentication requires a password.")

        if auth_type == Server.AuthenticationType.PRIVATE_KEY and not private_key:
            self.add_error("private_key", "Private key authentication requires a private key.")

        return cleaned_data

    def save(self, commit=True):
        server = super().save(commit=False)

        if self.cleaned_data.get("password"):
            server.set_password(self.cleaned_data["password"])
        if self.cleaned_data.get("private_key"):
            server.set_private_key(self.cleaned_data["private_key"])
        if self.cleaned_data.get("sudo_password"):
            server.set_sudo_password(self.cleaned_data["sudo_password"])

        if commit:
            server.save()
        return server