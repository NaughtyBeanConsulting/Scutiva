from django import forms

from core.forms import StyledFormMixin

from .models import VulnerabilityFinding


class VulnerabilityTriageForm(StyledFormMixin, forms.ModelForm):
    class Meta:
        model = VulnerabilityFinding
        fields = ["status", "remediation_notes", "fix_available", "exploit_known", "cisa_kev"]