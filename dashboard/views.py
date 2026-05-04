from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Count
from django.views.generic import TemplateView

from scanners.models import ComplianceFinding, ScanJob
from servers.models import Application, Server
from vulnerabilities.models import VulnerabilityFinding


class DashboardView(LoginRequiredMixin, TemplateView):
	template_name = "dashboard/index.html"

	def get_context_data(self, **kwargs):
		context = super().get_context_data(**kwargs)
		findings = VulnerabilityFinding.objects.all()
		compliance_findings = ComplianceFinding.objects.all()
		recent_scans = ScanJob.objects.select_related("server", "application").order_by("-created_at")[:6]

		context.update(
			{
				"summary": {
					"total_servers": Server.objects.count(),
					"total_scans": ScanJob.objects.count(),
					"critical": findings.filter(severity=VulnerabilityFinding.Severity.CRITICAL).count(),
					"high": findings.filter(severity=VulnerabilityFinding.Severity.HIGH).count(),
					"medium": findings.filter(severity=VulnerabilityFinding.Severity.MEDIUM).count(),
					"low": findings.filter(severity=VulnerabilityFinding.Severity.LOW).count(),
					"known_exploited": findings.filter(cisa_kev=True).count(),
					"fixes_available": findings.filter(fix_available=True).count(),
					"no_fix": findings.filter(fix_available=False).count(),
					"compliance_high": compliance_findings.filter(severity__in=[ComplianceFinding.Severity.CRITICAL, ComplianceFinding.Severity.HIGH]).count(),
					"compliance_total": compliance_findings.count(),
				},
				"recent_scans": recent_scans,
				"top_servers": Server.objects.annotate(vuln_count=Count("findings")).order_by("-vuln_count", "name")[:5],
				"top_packages": findings.values("package_name").annotate(total=Count("id")).order_by("-total", "package_name")[:5],
				"top_apps": Application.objects.annotate(vuln_count=Count("findings")).order_by("-vuln_count", "name")[:5],
			}
		)
		return context
