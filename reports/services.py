import csv
import io
import json
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from vulnerabilities.models import VulnerabilityFinding


def _queryset_for_report(report):
    qs = VulnerabilityFinding.objects.select_related("server", "application").order_by("-last_seen", "-created_at")

    rt = report.report_type
    if rt == report.__class__.ReportType.CRITICAL:
        qs = qs.filter(severity=VulnerabilityFinding.Severity.CRITICAL)
    elif rt == report.__class__.ReportType.KEV:
        qs = qs.filter(cisa_kev=True)
    elif rt == report.__class__.ReportType.FIX_AVAILABLE:
        qs = qs.filter(fix_available=True)
    elif rt == report.__class__.ReportType.OPEN:
        qs = qs.filter(status=VulnerabilityFinding.Status.OPEN)
    elif rt == report.__class__.ReportType.SERVER:
        server_id = report.filters.get("server_id")
        if server_id:
            qs = qs.filter(server_id=server_id)
    elif rt == report.__class__.ReportType.APPLICATION:
        app_id = report.filters.get("application_id")
        if app_id:
            qs = qs.filter(application_id=app_id)

    return qs


_CSV_FIELDS = [
    "cve_id", "severity", "cvss_score", "package_name", "installed_version",
    "fixed_version", "package_type", "ecosystem", "affected_path",
    "server", "application", "source_scanner", "fix_available",
    "exploit_known", "cisa_kev", "status", "first_seen", "last_seen",
]


def _finding_to_dict(f):
    return {
        "cve_id": f.cve_id,
        "severity": f.severity,
        "cvss_score": str(f.cvss_score) if f.cvss_score is not None else "",
        "package_name": f.package_name,
        "installed_version": f.installed_version,
        "fixed_version": f.fixed_version,
        "package_type": f.package_type,
        "ecosystem": f.ecosystem,
        "affected_path": f.affected_path,
        "server": f.server.name if f.server_id else "",
        "application": f.application.name if f.application_id else "",
        "source_scanner": f.source_scanner,
        "fix_available": f.fix_available,
        "exploit_known": f.exploit_known,
        "cisa_kev": f.cisa_kev,
        "status": f.status,
        "first_seen": f.first_seen.isoformat() if f.first_seen else "",
        "last_seen": f.last_seen.isoformat() if f.last_seen else "",
    }


def generate_report(report):
    qs = _queryset_for_report(report)
    report_dir = Path(settings.MEDIA_ROOT) / "reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    timestamp = timezone.now().strftime("%Y%m%d-%H%M%S")
    fmt = report.output_format

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=_CSV_FIELDS)
        writer.writeheader()
        for finding in qs:
            writer.writerow(_finding_to_dict(finding))
        content = buf.getvalue().encode("utf-8")
        filename = f"report-{report.pk}-{timestamp}.csv"
    else:
        rows = [_finding_to_dict(f) for f in qs]
        payload = {
            "report": {
                "id": report.pk,
                "name": report.name,
                "type": report.report_type,
                "generated_at": timezone.now().isoformat(),
                "finding_count": len(rows),
            },
            "findings": rows,
        }
        content = json.dumps(payload, indent=2, default=str).encode("utf-8")
        filename = f"report-{report.pk}-{timestamp}.json"

    file_path = report_dir / filename
    file_path.write_bytes(content)
    report.file_path = str(file_path)
    report.save(update_fields=["file_path", "updated_at"])
    return file_path
