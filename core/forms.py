from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordChangeForm
from django.utils.text import slugify

from accounts.models import Organization
from scanners.models import ScanProfile


User = get_user_model()


FIELD_CLASSES = {
    forms.TextInput: "w-full rounded-2xl border border-slate-700 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 outline-none ring-0 placeholder:text-slate-500 focus:border-cyan-400",
    forms.EmailInput: "w-full rounded-2xl border border-slate-700 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 outline-none ring-0 placeholder:text-slate-500 focus:border-cyan-400",
    forms.PasswordInput: "w-full rounded-2xl border border-slate-700 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 outline-none ring-0 placeholder:text-slate-500 focus:border-cyan-400",
    forms.URLInput: "w-full rounded-2xl border border-slate-700 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 outline-none ring-0 placeholder:text-slate-500 focus:border-cyan-400",
    forms.NumberInput: "w-full rounded-2xl border border-slate-700 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 outline-none ring-0 placeholder:text-slate-500 focus:border-cyan-400",
    forms.Select: "w-full rounded-2xl border border-slate-700 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 outline-none ring-0 focus:border-cyan-400",
    forms.Textarea: "w-full rounded-2xl border border-slate-700 bg-slate-950/80 px-4 py-3 text-sm text-slate-100 outline-none ring-0 placeholder:text-slate-500 focus:border-cyan-400 min-h-28",
    forms.CheckboxInput: "h-4 w-4 rounded border-slate-700 bg-slate-950 text-cyan-400 focus:ring-cyan-400",
}


def style_form_fields(form):
    for field in form.fields.values():
        for widget_type, css_class in FIELD_CLASSES.items():
            if isinstance(field.widget, widget_type):
                existing = field.widget.attrs.get("class", "")
                field.widget.attrs["class"] = f"{existing} {css_class}".strip()
                break


class StyledFormMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        style_form_fields(self)


class UserProfileForm(StyledFormMixin, forms.ModelForm):
    class Meta:
        model = User
        fields = ["full_name", "email"]

    def clean_email(self):
        email = self.cleaned_data["email"]
        if User.objects.exclude(pk=self.instance.pk).filter(email__iexact=email).exists():
            raise forms.ValidationError("This email address is already in use.")
        return email.lower()


class StyledPasswordChangeForm(StyledFormMixin, PasswordChangeForm):
    pass


class OrganisationForm(StyledFormMixin, forms.ModelForm):
    class Meta:
        model = Organization
        fields = ["name", "slug"]

    def clean_slug(self):
        slug = self.cleaned_data.get("slug") or slugify(self.cleaned_data.get("name", ""))
        if Organization.objects.exclude(pk=self.instance.pk if self.instance.pk else None).filter(slug=slug).exists():
            raise forms.ValidationError("This slug is already taken.")
        return slug


class DefaultScanProfileForm(StyledFormMixin, forms.Form):
    default_profile = forms.ModelChoiceField(
        queryset=ScanProfile.objects.all().order_by("name"),
        required=False,
        empty_label="— No default —",
        label="Default scan profile",
        help_text="Applied automatically when queuing scans without an explicit profile.",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        style_form_fields(self)
