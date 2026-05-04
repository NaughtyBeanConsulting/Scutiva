from django import forms

from core.forms import StyledFormMixin
from servers.models import Application, Server

from .models import ScanJob, ScanProfile


class ScanProfileForm(StyledFormMixin, forms.ModelForm):
    class Meta:
        model = ScanProfile
        fields = [
            "name",
            "description",
            "scan_os_packages",
            "scan_application_directories",
            "scan_docker_images",
            "scan_containers",
            "scan_dependency_manifests",
            "scan_iac_files",
            "scan_shell_scripts",
            "enable_syft",
            "enable_grype",
            "enable_trivy",
            "enable_lynis",
            "enable_openscap",
            "openscap_profile",
            "include_dev_dependencies",
            "severity_threshold",
            "include_paths",
            "exclude_paths",
            "schedule",
            "is_default",
        ]


class QueueScanJobForm(StyledFormMixin, forms.Form):
    server = forms.ModelChoiceField(queryset=Server.objects.filter(is_active=True).order_by("name"))
    application = forms.ModelChoiceField(
        queryset=Application.objects.select_related("server").order_by("server__name", "name"),
        required=False,
    )
    scan_profile = forms.ModelChoiceField(queryset=ScanProfile.objects.order_by("name"), required=False)

    def clean(self):
        cleaned_data = super().clean()
        application = cleaned_data.get("application")
        server = cleaned_data.get("server")
        if application and server and application.server_id != server.id:
            self.add_error("application", "Selected application does not belong to the selected server.")
        return cleaned_data