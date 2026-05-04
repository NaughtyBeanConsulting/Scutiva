from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponseBadRequest
from django.shortcuts import get_object_or_404, render
from django.urls import reverse_lazy
from django.views import View
from django.views.generic import CreateView, DetailView, ListView, UpdateView

from .forms import ServerForm
from .models import Application, Server
from .services import test_ssh_connection


class ServerWorkspaceMixin:
    template_name = "servers/form.html"
    partial_template_name = "servers/_form_panel.html"

    def get_template_names(self):
        if self.request.headers.get("HX-Request"):
            return [self.partial_template_name]
        return [self.template_name]

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["servers"] = Server.objects.order_by("name")
        return context

    def form_invalid(self, form):
        response = render(self.request, self.partial_template_name, self.get_context_data(form=form, object=getattr(self, "object", None)))
        response.status_code = 422
        return response

    def form_valid(self, form):
        if not getattr(form.instance, "created_by_id", None):
            form.instance.created_by = self.request.user
        self.object = form.save()
        messages.success(self.request, "Server saved successfully.")
        if self.request.headers.get("HX-Request"):
            return render(
                self.request,
                "servers/_save_response.html",
                {
                    "servers": Server.objects.order_by("name"),
                    "server": self.object,
                },
            )
        return super().form_valid(form)


class ServerListView(LoginRequiredMixin, ListView):
    model = Server
    template_name = "servers/list.html"
    context_object_name = "servers"


class ServerDetailView(LoginRequiredMixin, DetailView):
    model = Server
    template_name = "servers/detail.html"
    context_object_name = "server"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["recent_jobs"] = self.object.scan_jobs.order_by("-created_at")[:8]
        context["installation"] = getattr(self.object, "scanner_installation", None)
        return context


class ServerActivityView(LoginRequiredMixin, DetailView):
    model = Server
    template_name = "servers/_activity_panel.html"
    context_object_name = "server"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["recent_jobs"] = self.object.scan_jobs.order_by("-created_at")[:8]
        context["installation"] = getattr(self.object, "scanner_installation", None)
        return context


class ServerCreateView(LoginRequiredMixin, ServerWorkspaceMixin, CreateView):
    model = Server
    form_class = ServerForm
    success_url = reverse_lazy("servers:list")


class ServerUpdateView(LoginRequiredMixin, ServerWorkspaceMixin, UpdateView):
    model = Server
    form_class = ServerForm
    success_url = reverse_lazy("servers:list")


class ApplicationListView(LoginRequiredMixin, ListView):
    model = Application
    template_name = "servers/applications.html"
    context_object_name = "applications"

    def get_queryset(self):
        return Application.objects.select_related("server").order_by("server__name", "name")


class TestConnectionView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        form = ServerForm(request.POST)
        if not form.is_valid():
            return HttpResponseBadRequest(
                render(
                    request,
                    "servers/_connection_result.html",
                    {"ok": False, "message": "Fix the highlighted form errors before testing."},
                ).content
            )

        ok, message = test_ssh_connection(form.cleaned_data)
        return render(request, "servers/_connection_result.html", {"ok": ok, "message": message})


class ServerInstallerContextView(LoginRequiredMixin, DetailView):
    model = Server
    template_name = "servers/detail.html"

    def get_object(self, queryset=None):
        return get_object_or_404(Server, pk=self.kwargs["pk"])
