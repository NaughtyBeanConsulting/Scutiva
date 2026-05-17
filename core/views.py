from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect, render
from django.views import View
from django.views.generic import TemplateView

from accounts.models import Organization
from scanners.models import ScanProfile

from .forms import DefaultScanProfileForm, OrganisationForm, StyledPasswordChangeForm, UserProfileForm


class SettingsView(LoginRequiredMixin, TemplateView):
    template_name = "settings/index.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user = self.request.user
        org = user.organization
        context["profile_form"] = kwargs.get("profile_form", UserProfileForm(instance=user))
        context["password_form"] = kwargs.get("password_form", StyledPasswordChangeForm(user=user))
        context["org_form"] = kwargs.get("org_form", OrganisationForm(instance=org) if org else OrganisationForm())
        context["org"] = org
        current_default = ScanProfile.objects.filter(is_default=True).first()
        context["scan_profile_form"] = kwargs.get(
            "scan_profile_form",
            DefaultScanProfileForm(initial={"default_profile": current_default}),
        )
        return context


class ProfileUpdateView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        form = UserProfileForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, "Profile updated successfully.")
            return redirect("core:settings")
        return render(request, "settings/index.html", SettingsView(request=request).get_context_data(profile_form=form))


class PasswordUpdateView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        form = StyledPasswordChangeForm(user=request.user, data=request.POST)
        if form.is_valid():
            form.save()
            update_session_auth_hash(request, form.user)
            messages.success(request, "Password changed successfully.")
            return redirect("core:settings")
        return render(request, "settings/index.html", SettingsView(request=request).get_context_data(password_form=form))


class OrganisationUpdateView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        org = request.user.organization
        form = OrganisationForm(request.POST, instance=org)
        if form.is_valid():
            saved_org = form.save()
            if org is None:
                request.user.organization = saved_org
                request.user.save(update_fields=["organization"])
            messages.success(request, "Organisation updated successfully.")
            return redirect("core:settings")
        return render(request, "settings/index.html", SettingsView(request=request).get_context_data(org_form=form))


class DefaultScanProfileUpdateView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        form = DefaultScanProfileForm(request.POST)
        if form.is_valid():
            ScanProfile.objects.update(is_default=False)
            chosen = form.cleaned_data["default_profile"]
            if chosen:
                chosen.is_default = True
                chosen.save(update_fields=["is_default", "updated_at"])
            messages.success(request, "Default scan profile updated.")
            return redirect("core:settings")
        return render(request, "settings/index.html", SettingsView(request=request).get_context_data(scan_profile_form=form))
