import json
import re
import shlex
import xml.etree.ElementTree as ET
from collections import Counter
from decimal import Decimal
from hashlib import sha1
from pathlib import Path
from textwrap import dedent

from django.conf import settings
from django.db import transaction
from django.utils import timezone

from sboms.models import SBOMArtifact
from servers.models import Application
from servers.services import download_text, run_remote_command, upload_text
from vulnerabilities.models import VulnerabilityFinding

from .models import ComplianceFinding, ScanJob, ScanProfile, ScannerInstallation


def _clamp_progress(value):
  return max(0, min(100, int(value)))


def _trim_command(command):
  if not command:
    return ""
  if len(command) <= 500:
    return command
  return command[:497] + "..."


def update_job_progress(
  job,
  *,
  stage=None,
  status=None,
  error_logs=None,
  ended_at=None,
  progress_percent=None,
  current_command=None,
  clear_current_command=False,
  message=None,
  details=None,
):
  changed_fields = ["updated_at"]
  if stage is not None:
    job.stage = stage
    changed_fields.append("stage")
  if status is not None:
    job.status = status
    changed_fields.append("status")
  if progress_percent is not None:
    job.progress_percent = _clamp_progress(progress_percent)
    changed_fields.append("progress_percent")
  if current_command is not None:
    job.current_command = _trim_command(current_command)
    changed_fields.append("current_command")
  elif clear_current_command:
    job.current_command = ""
    changed_fields.append("current_command")
  if error_logs is not None:
    job.error_logs = error_logs
    changed_fields.append("error_logs")
  if ended_at is not None:
    job.ended_at = ended_at
    changed_fields.append("ended_at")
  if any(value is not None for value in [stage, progress_percent, current_command, message, details]) or clear_current_command:
    context = dict(job.progress_context or {})
    timestamp = timezone.now().isoformat()
    context["updated_at"] = timestamp
    if message:
      context["last_message"] = message
    if details is not None:
      context["details"] = details
    event = {"timestamp": timestamp}
    if stage is not None:
      event["stage"] = stage
    if progress_percent is not None:
      event["progress_percent"] = job.progress_percent
    if message:
      event["message"] = message
    if current_command is not None:
      event["current_command"] = job.current_command
    elif clear_current_command:
      event["current_command"] = ""
    if details is not None:
      event["details"] = details
    if len(event) > 1:
      events = list(context.get("events", []))
      events.append(event)
      context["events"] = events[-12:]
    job.progress_context = context
    changed_fields.append("progress_context")
  job.save(update_fields=changed_fields)


def run_job_command(job, command, *, stage, progress_percent, message, sudo=False, timeout=300):
  update_job_progress(
    job,
    stage=stage,
    progress_percent=progress_percent,
    current_command=command,
    message=message,
  )
  ensure_job_not_cancelled(job)
  return run_remote_command(job.server, command, sudo=sudo, timeout=timeout)


def ensure_job_not_cancelled(job):
  job.refresh_from_db(fields=["status", "cancellation_requested", "error_logs"])
  if job.cancellation_requested or job.status == ScanJob.Status.CANCELLED:
    update_job_progress(
      job,
      stage=ScanJob.Stage.CANCELLED,
      status=ScanJob.Status.CANCELLED,
      clear_current_command=True,
      ended_at=timezone.now(),
      message="Job cancelled by user.",
      error_logs=job.error_logs or "Job cancelled by user.",
    )
    raise RuntimeError("Job cancelled by user.")


def generate_installer_script():
    return dedent(
        """
        #!/usr/bin/env bash
        set -euo pipefail

        if [[ "$(id -u)" -ne 0 ]]; then
          echo "Run as root or with sudo."
          exit 1
        fi

        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y curl wget gnupg lsb-release ca-certificates jq lynis libopenscap8 openscap-scanner ssg-base

        curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
        curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor -o /usr/share/keyrings/trivy.gpg
        echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" > /etc/apt/sources.list.d/trivy.list
        apt-get update
        apt-get install -y trivy

        echo "Installed versions:"
        syft version || true
        grype version || true
        trivy version || true
        lynis show version || true
        oscap --version || true
        """
    ).strip()


DISCOVERY_SCRIPT = dedent(
  """
  import json
  import os

  ROOTS = {roots}
  MANIFESTS = [
      "requirements.txt", "pyproject.toml", "Pipfile.lock", "poetry.lock",
      "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
      "composer.lock", "Gemfile.lock", "pom.xml", "build.gradle", "go.mod",
      "Cargo.lock", ".csproj", "packages.lock.json", "Dockerfile",
      "docker-compose.yml", "docker-compose.yaml", "main.tf", "terraform.tfvars",
  ]

  def classify(files):
      file_set = set(files)
      if "pyproject.toml" in file_set or "requirements.txt" in file_set:
          language = "Python"
          framework = "Django" if os.path.exists(os.path.join(current_path, "manage.py")) else "Python"
          package_manager = "pip"
      elif "package.json" in file_set:
          language = "JavaScript"
          framework = "Node.js"
          package_manager = "npm"
      elif "composer.lock" in file_set:
          language = "PHP"
          framework = "Laravel"
          package_manager = "composer"
      elif "pom.xml" in file_set or "build.gradle" in file_set:
          language = "Java"
          framework = "Spring Boot"
          package_manager = "maven" if "pom.xml" in file_set else "gradle"
      elif "go.mod" in file_set:
          language = "Go"
          framework = "Go"
          package_manager = "go"
      else:
          language = "Unknown"
          framework = "Unknown"
          package_manager = "Unknown"
      return language, framework, package_manager

  results = []
  seen = set()
  for root in ROOTS:
      if not os.path.isdir(root):
          continue
      for current_path, dirs, files in os.walk(root):
          manifests = sorted([name for name in files if name in MANIFESTS])
          if not manifests:
              continue
          key = os.path.abspath(current_path)
          if key in seen:
              continue
          seen.add(key)
          language, framework, package_manager = classify(files)
          git_dir = os.path.join(current_path, ".git")
          dockerfile_present = "Dockerfile" in files
          docker_compose_present = "docker-compose.yml" in files or "docker-compose.yaml" in files
          results.append({
              "name": os.path.basename(current_path) or current_path,
              "path": current_path,
              "project_type": framework,
              "framework": framework,
              "language": language,
              "dependency_files": manifests,
              "package_manager": package_manager,
              "dockerfile_present": dockerfile_present,
              "docker_compose_present": docker_compose_present,
              "git_repository_url": "",
              "git_branch": "",
              "git_commit_hash": "",
          })
          dirs[:] = [name for name in dirs if name not in {"node_modules", ".venv", "venv", ".git", "dist", "build", "__pycache__"}]

  print(json.dumps(results))
  """
)


def _job_media_dir(job):
  job_dir = Path(settings.MEDIA_ROOT) / "scan_jobs" / f"job-{job.pk}"
  job_dir.mkdir(parents=True, exist_ok=True)
  return job_dir


def _extract_version(output, tool_name):
  pattern = re.compile(rf"{tool_name}[^\n]*?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)
  match = pattern.search(output)
  return match.group(1) if match else ""


def _save_text(path, content):
  path.write_text(content, encoding="utf-8")


def _severity_value(value):
  value = (value or "unknown").lower()
  if value in {choice for choice, _ in VulnerabilityFinding.Severity.choices}:
    return value
  return VulnerabilityFinding.Severity.UNKNOWN


def _compliance_severity_value(value):
  value = (value or "unknown").lower()
  if value in {choice for choice, _ in ComplianceFinding.Severity.choices}:
    return value
  if value == "negligible":
    return ComplianceFinding.Severity.INFO
  return ComplianceFinding.Severity.UNKNOWN


def _decimal_score(value):
  if value in (None, ""):
    return None
  try:
    return Decimal(str(value)).quantize(Decimal("0.1"))
  except Exception:
    return None


def _resolve_scan_target(job):
  profile = job.scan_profile
  if job.application_id:
    return job.application.path
  if profile and profile.include_paths.strip():
    return profile.include_paths.splitlines()[0].strip()
  return "/"


def _upsert_finding(job, source_scanner, cve_id, defaults):
  lookup = {
    "server": job.server,
    "application": job.application,
    "source_scanner": source_scanner,
    "cve_id": cve_id,
    "package_name": defaults.get("package_name", "unknown"),
    "affected_path": defaults.get("affected_path", ""),
  }
  now = timezone.now()
  obj, created = VulnerabilityFinding.objects.get_or_create(
    **lookup,
    defaults={
      **defaults,
      "scan_job": job,
      "first_seen": now,
      "last_seen": now,
    },
  )
  if not created:
    current_status = obj.status
    for field, value in defaults.items():
      setattr(obj, field, value)
    obj.scan_job = job
    obj.last_seen = now
    obj.status = current_status
    obj.save()
  return obj


def _stable_control_id(prefix, text):
  digest = sha1((text or prefix).encode("utf-8")).hexdigest()[:12]
  return f"{prefix}-{digest}"


def _upsert_compliance_finding(job, source_scanner, control_id, defaults):
  lookup = {
    "server": job.server,
    "application": job.application,
    "source_scanner": source_scanner,
    "control_id": control_id,
    "resource": defaults.get("resource", ""),
  }
  now = timezone.now()
  obj, created = ComplianceFinding.objects.get_or_create(
    **lookup,
    defaults={
      **defaults,
      "scan_job": job,
      "first_seen": now,
      "last_seen": now,
    },
  )
  if not created:
    current_status = obj.status
    for field, value in defaults.items():
      setattr(obj, field, value)
    obj.scan_job = job
    obj.last_seen = now
    obj.status = current_status
    obj.save()
  return obj


def _parse_grype_results(job, payload):
  count = 0
  for match in payload.get("matches", []):
    vulnerability = match.get("vulnerability", {})
    artifact = match.get("artifact", {})
    locations = artifact.get("locations") or [{}]
    cvss_entries = vulnerability.get("cvss") or []
    cvss_score = None
    for entry in cvss_entries:
      metrics = entry.get("metrics") or {}
      cvss_score = metrics.get("baseScore") or metrics.get("base_score")
      if cvss_score is not None:
        break

    default_values = {
      "severity": _severity_value(vulnerability.get("severity")),
      "cvss_score": _decimal_score(cvss_score),
      "package_name": artifact.get("name", "unknown"),
      "installed_version": artifact.get("version", ""),
      "fixed_version": ", ".join(vulnerability.get("fix", {}).get("versions", [])[:3]),
      "package_type": artifact.get("type", ""),
      "ecosystem": artifact.get("language", ""),
      "affected_path": locations[0].get("path", ""),
      "description": vulnerability.get("description", ""),
      "references": vulnerability.get("urls", []),
      "fix_available": bool(vulnerability.get("fix", {}).get("versions")),
      "exploit_known": False,
      "cisa_kev": False,
      "raw_output": json.dumps(match),
    }
    _upsert_finding(job, "grype", vulnerability.get("id", "UNKNOWN"), default_values)
    count += 1
  return count


def _parse_trivy_results(job, payload):
  count = 0
  for result in payload.get("Results", []):
    for vulnerability in result.get("Vulnerabilities", []) or []:
      cvss_payload = vulnerability.get("CVSS") or {}
      cvss_score = None
      for vendor_score in cvss_payload.values():
        cvss_score = vendor_score.get("V3Score") or vendor_score.get("V2Score")
        if cvss_score is not None:
          break
      default_values = {
        "severity": _severity_value(vulnerability.get("Severity")),
        "cvss_score": _decimal_score(cvss_score),
        "package_name": vulnerability.get("PkgName", "unknown"),
        "installed_version": vulnerability.get("InstalledVersion", ""),
        "fixed_version": vulnerability.get("FixedVersion", ""),
        "package_type": result.get("Class", result.get("Type", "")),
        "ecosystem": result.get("Type", ""),
        "affected_path": result.get("Target", ""),
        "description": vulnerability.get("Description", ""),
        "references": vulnerability.get("References", []),
        "fix_available": bool(vulnerability.get("FixedVersion")),
        "exploit_known": False,
        "cisa_kev": False,
        "raw_output": json.dumps(vulnerability),
      }
      _upsert_finding(job, "trivy", vulnerability.get("VulnerabilityID", "UNKNOWN"), default_values)
      count += 1
  return count


def _parse_trivy_compliance_results(job, payload):
  counts = Counter()
  for result in payload.get("Results", []):
    target = result.get("Target", "")
    for misconfiguration in result.get("Misconfigurations", []) or []:
      control_id = misconfiguration.get("ID") or _stable_control_id("trivy-misconfig", json.dumps(misconfiguration, sort_keys=True))
      _upsert_compliance_finding(
        job,
        "trivy",
        control_id,
        {
          "benchmark": result.get("Type", "trivy-misconfig"),
          "title": misconfiguration.get("Title") or misconfiguration.get("Message") or control_id,
          "severity": _compliance_severity_value(misconfiguration.get("Severity")),
          "resource": target,
          "description": misconfiguration.get("Description", ""),
          "remediation": misconfiguration.get("Resolution", ""),
          "references": misconfiguration.get("References", []),
          "raw_output": json.dumps(misconfiguration),
        },
      )
      counts["trivy_misconfig"] += 1

    for secret in result.get("Secrets", []) or []:
      control_id = secret.get("RuleID") or _stable_control_id("trivy-secret", json.dumps(secret, sort_keys=True))
      description = secret.get("Match", "")
      if description and len(description) > 180:
        description = description[:177] + "..."
      _upsert_compliance_finding(
        job,
        "trivy",
        control_id,
        {
          "benchmark": "trivy-secret",
          "title": secret.get("Title") or secret.get("RuleID") or "Potential secret exposed",
          "severity": _compliance_severity_value(secret.get("Severity") or "high"),
          "resource": target,
          "description": description,
          "remediation": "Rotate and remove exposed credentials or tokens from the codebase and history.",
          "references": [],
          "raw_output": json.dumps(secret),
        },
      )
      counts["trivy_secret"] += 1
  return counts


def _parse_lynis_report(job, report_text):
  counts = Counter()
  for line in report_text.splitlines():
    line = line.strip()
    if not line or "=" not in line:
      continue
    key, value = line.split("=", 1)
    if key not in {"warning[]", "suggestion[]"}:
      continue
    severity = ComplianceFinding.Severity.MEDIUM if key == "warning[]" else ComplianceFinding.Severity.LOW
    control_id = _stable_control_id("lynis", value)
    _upsert_compliance_finding(
      job,
      "lynis",
      control_id,
      {
        "benchmark": "lynis-host-hardening",
        "title": value[:500],
        "severity": severity,
        "resource": job.server.host,
        "description": value,
        "remediation": value,
        "references": [],
        "raw_output": line,
      },
    )
    counts["lynis"] += 1
  return counts


def _parse_openscap_results(job, xml_text, benchmark):
  counts = Counter()
  if not xml_text.strip():
    return counts

  root = ET.fromstring(xml_text)
  rules = {}
  for element in root.iter():
    if element.tag.endswith("Rule"):
      rule_id = element.attrib.get("id") or ""
      if not rule_id:
        continue
      title = ""
      description = ""
      for child in element:
        if child.tag.endswith("title") and not title:
          title = (child.text or "").strip()
        elif child.tag.endswith("description") and not description:
          description = "".join(child.itertext()).strip()
      rules[rule_id] = {
        "title": title or rule_id,
        "description": description,
        "severity": _compliance_severity_value(element.attrib.get("severity")),
      }

  for element in root.iter():
    if not element.tag.endswith("rule-result"):
      continue
    control_id = element.attrib.get("idref") or _stable_control_id("openscap", ET.tostring(element, encoding="unicode"))
    result_value = ""
    for child in element:
      if child.tag.endswith("result"):
        result_value = (child.text or "").strip().lower()
        break
    if result_value not in {"fail", "error", "unknown", "notchecked"}:
      continue
    metadata = rules.get(control_id, {})
    _upsert_compliance_finding(
      job,
      "openscap",
      control_id,
      {
        "benchmark": benchmark,
        "title": metadata.get("title") or f"OpenSCAP rule {control_id}",
        "severity": metadata.get("severity") or ComplianceFinding.Severity.MEDIUM,
        "resource": job.server.host,
        "description": metadata.get("description") or f"Rule result: {result_value}",
        "remediation": f"Review and remediate rule {control_id} for benchmark {benchmark}.",
        "references": [],
        "raw_output": ET.tostring(element, encoding="unicode"),
      },
    )
    counts["openscap"] += 1
  return counts


def enqueue_scan_job(*, server, queue_name, user=None, application=None, scan_profile=None):
  job = ScanJob.objects.create(
    server=server,
    application=application,
    scan_profile=scan_profile,
    queue_name=queue_name,
    status=ScanJob.Status.QUEUED,
    stage=ScanJob.Stage.QUEUED,
    progress_percent=0,
    progress_context={"last_message": "Job queued.", "events": []},
  )
  return job


def execute_install_job(job):
  update_job_progress(job, stage=ScanJob.Stage.INSTALLING_TOOLS, progress_percent=15, message="Uploading and running installer.")
  ensure_job_not_cancelled(job)
  installation, _ = ScannerInstallation.objects.get_or_create(server=job.server)
  installation.status = ScannerInstallation.Status.INSTALLING
  installation.save(update_fields=["status", "updated_at"])

  remote_script_path = f"/tmp/scutiva-install-{job.pk}.sh"
  upload_text(job.server, generate_installer_script(), remote_script_path, mode=0o700)
  result = run_job_command(
    job,
    remote_script_path,
    stage=ScanJob.Stage.INSTALLING_TOOLS,
    progress_percent=30,
    message="Running installer on remote server.",
    sudo=True,
    timeout=1800,
  )

  job_dir = _job_media_dir(job)
  _save_text(job_dir / "install.log", result.stdout + "\n" + result.stderr)

  if result.exit_status != 0:
    installation.status = ScannerInstallation.Status.FAILED
    installation.install_logs = result.stdout + "\n" + result.stderr
    installation.save()
    raise RuntimeError(result.stderr or result.stdout or "Scanner installation failed.")

  ensure_job_not_cancelled(job)
  version_output = run_job_command(
    job,
    "syft version && grype version && trivy version && lynis show version && oscap --version",
    stage=ScanJob.Stage.INSTALLING_TOOLS,
    progress_percent=80,
    message="Collecting installed scanner versions.",
    sudo=False,
    timeout=120,
  )
  combined_output = result.stdout + "\n" + version_output.stdout
  installation.status = ScannerInstallation.Status.INSTALLED
  installation.syft_version = _extract_version(combined_output, "syft")
  installation.grype_version = _extract_version(combined_output, "grype")
  installation.trivy_version = _extract_version(combined_output, "trivy")
  installation.lynis_version = _extract_version(combined_output, "lynis")
  installation.openscap_version = _extract_version(combined_output, "oscap")
  installation.last_install_date = timezone.now()
  installation.install_logs = combined_output + "\n" + result.stderr + version_output.stderr
  installation.save()
  job.raw_output_path = str(job_dir)
  job.tools_used = ["syft", "grype", "trivy", "lynis", "openscap"]
  job.parsed_findings = [{"action": "install", "status": "installed"}]


def execute_discovery_job(job):
  update_job_progress(job, stage=ScanJob.Stage.DISCOVERING_APPS, progress_percent=20, message="Preparing remote discovery script.")
  ensure_job_not_cancelled(job)
  roots = job.server.get_codebase_paths()
  if not roots:
    raise ValueError("No codebase paths configured on the server.")

  script = DISCOVERY_SCRIPT.format(roots=json.dumps(roots))
  remote_python = "python3 - <<'PY'\n" + script + "\nPY"
  result = run_job_command(
    job,
    remote_python,
    stage=ScanJob.Stage.DISCOVERING_APPS,
    progress_percent=55,
    message="Discovering application roots and manifests.",
    sudo=False,
    timeout=900,
  )
  job_dir = _job_media_dir(job)
  _save_text(job_dir / "discovery.json", result.stdout)
  if result.exit_status != 0:
    raise RuntimeError(result.stderr or "Application discovery failed.")

  payload = json.loads(result.stdout or "[]")
  update_job_progress(job, stage=ScanJob.Stage.PARSING_RESULTS, progress_percent=85, message="Persisting discovered applications.")
  applications = []
  for item in payload:
    application, _ = Application.objects.update_or_create(
      server=job.server,
      path=item["path"],
      defaults={
        "name": item["name"],
        "project_type": item.get("project_type", ""),
        "framework": item.get("framework", ""),
        "language": item.get("language", ""),
        "dependency_files": item.get("dependency_files", []),
        "git_repository_url": item.get("git_repository_url", ""),
        "git_branch": item.get("git_branch", ""),
        "git_commit_hash": item.get("git_commit_hash", ""),
        "package_manager": item.get("package_manager", ""),
        "dockerfile_present": item.get("dockerfile_present", False),
        "docker_compose_present": item.get("docker_compose_present", False),
        "last_discovered_at": timezone.now(),
      },
    )
    applications.append({"name": application.name, "path": application.path})

  job.raw_output_path = str(job_dir)
  job.tools_used = ["discovery"]
  job.parsed_findings = applications


def execute_scan_job(job):
  target_path = _resolve_scan_target(job)
  job_dir = _job_media_dir(job)
  remote_dir = f"/tmp/scutiva-job-{job.pk}"
  profile = job.scan_profile or ScanProfile.objects.filter(is_default=True).first()
  tools_used = []
  scan_warnings = []
  quoted_target_path = shlex.quote(target_path)

  update_job_progress(job, stage=ScanJob.Stage.PREPARING_TARGET, progress_percent=10, message="Preparing remote workspace.")
  ensure_job_not_cancelled(job)
  setup_result = run_job_command(
    job,
    f"mkdir -p {remote_dir}",
    stage=ScanJob.Stage.PREPARING_TARGET,
    progress_percent=18,
    message="Creating remote job directory.",
    sudo=True,
    timeout=120,
  )
  if setup_result.exit_status != 0:
    raise RuntimeError(setup_result.stderr or "Failed to prepare remote scan directory.")

  if not profile or profile.enable_syft:
    tools_used.append("syft")
    update_job_progress(job, stage=ScanJob.Stage.BUILDING_SBOM, progress_percent=35, message="Building SBOM with Syft.")
    ensure_job_not_cancelled(job)
    syft_command = f"syft {quoted_target_path} -o json > {remote_dir}/sbom.json"
    result = run_job_command(
      job,
      syft_command,
      stage=ScanJob.Stage.BUILDING_SBOM,
      progress_percent=42,
      message="Running Syft to generate SBOM.",
      sudo=True,
      timeout=1800,
    )
    if result.exit_status != 0:
      raise RuntimeError(result.stderr or "Syft scan failed.")
    payload = download_text(job.server, f"{remote_dir}/sbom.json")
    _save_text(job_dir / "sbom.json", payload)
    SBOMArtifact.objects.create(
      server=job.server,
      application=job.application,
      generated_by="syft",
      format="json",
      file_path=str(job_dir / "sbom.json"),
      package_count=len(json.loads(payload or "{}").get("artifacts", [])),
      related_scan=job,
    )

  findings_summary = Counter()
  if not profile or profile.enable_grype:
    tools_used.append("grype")
    update_job_progress(job, stage=ScanJob.Stage.RUNNING_GRYPE, progress_percent=58, message="Running Grype against the SBOM.")
    ensure_job_not_cancelled(job)
    grype_command = f"grype sbom:{remote_dir}/sbom.json -o json > {remote_dir}/grype.json"
    result = run_job_command(
      job,
      grype_command,
      stage=ScanJob.Stage.RUNNING_GRYPE,
      progress_percent=64,
      message="Executing Grype scan.",
      sudo=True,
      timeout=1800,
    )
    if result.exit_status == 0:
      update_job_progress(job, stage=ScanJob.Stage.PARSING_RESULTS, progress_percent=72, message="Parsing Grype results.")
      payload = json.loads(download_text(job.server, f"{remote_dir}/grype.json") or "{}")
      _save_text(job_dir / "grype.json", json.dumps(payload, indent=2))
      findings_summary["grype"] = _parse_grype_results(job, payload)
    else:
      findings_summary["grype_error"] = 1
      scan_warnings.append("Grype scan did not complete successfully.")

  if not profile or profile.enable_trivy:
    tools_used.append("trivy")
    update_job_progress(job, stage=ScanJob.Stage.RUNNING_TRIVY, progress_percent=78, message="Running Trivy filesystem scan.")
    ensure_job_not_cancelled(job)
    trivy_command = f"trivy fs --skip-db-update --scanners vuln,misconfig,secret,license --format json -o {remote_dir}/trivy.json {quoted_target_path}"
    result = run_job_command(
      job,
      trivy_command,
      stage=ScanJob.Stage.RUNNING_TRIVY,
      progress_percent=84,
      message="Executing Trivy scan.",
      sudo=True,
      timeout=1800,
    )
    if result.exit_status == 0:
      update_job_progress(job, stage=ScanJob.Stage.PARSING_RESULTS, progress_percent=92, message="Parsing Trivy results.")
      payload = json.loads(download_text(job.server, f"{remote_dir}/trivy.json") or "{}")
      _save_text(job_dir / "trivy.json", json.dumps(payload, indent=2))
      findings_summary["trivy"] = _parse_trivy_results(job, payload)
      findings_summary.update(_parse_trivy_compliance_results(job, payload))
    else:
      findings_summary["trivy_error"] = 1
      scan_warnings.append("Trivy scan did not complete successfully.")

  if not profile or profile.enable_lynis:
    tools_used.append("lynis")
    update_job_progress(job, stage=ScanJob.Stage.RUNNING_LYNIS, progress_percent=90, message="Running Lynis host hardening audit.")
    ensure_job_not_cancelled(job)
    lynis_command = f"lynis audit system --quick --quiet --report-file {remote_dir}/lynis-report.dat --logfile {remote_dir}/lynis.log"
    result = run_job_command(
      job,
      lynis_command,
      stage=ScanJob.Stage.RUNNING_LYNIS,
      progress_percent=93,
      message="Executing Lynis audit.",
      sudo=True,
      timeout=2400,
    )
    if result.exit_status == 0:
      report_text = download_text(job.server, f"{remote_dir}/lynis-report.dat") or ""
      log_text = download_text(job.server, f"{remote_dir}/lynis.log") or ""
      _save_text(job_dir / "lynis-report.dat", report_text)
      _save_text(job_dir / "lynis.log", log_text)
      findings_summary.update(_parse_lynis_report(job, report_text))
    else:
      findings_summary["lynis_error"] = 1
      scan_warnings.append("Lynis audit did not complete successfully.")

  if not profile or profile.enable_openscap:
    tools_used.append("openscap")
    update_job_progress(job, stage=ScanJob.Stage.RUNNING_OPENSCAP, progress_percent=95, message="Running OpenSCAP benchmark evaluation.")
    ensure_job_not_cancelled(job)
    openscap_profile = profile.openscap_profile if profile and profile.openscap_profile else "xccdf_org.ssgproject.content_profile_cis_level1_server"
    openscap_command = (
      "bash -lc '"
      "set +e; "
      "DATASTREAM=$(find /usr/share/xml/scap/ssg/content -maxdepth 1 -type f -name \"ssg-ubuntu*-ds.xml\" | sort | tail -n 1); "
      "if [[ -z \"$DATASTREAM\" ]]; then echo \"No Ubuntu SCAP datastream found.\"; exit 2; fi; "
      f"oscap xccdf eval --profile {shlex.quote(openscap_profile)} --results {remote_dir}/oscap-results.xml --report {remote_dir}/oscap-report.html \"$DATASTREAM\"; "
      "code=$?; echo __SCUTIVA_OSCAP_EXIT__=$code; exit 0'"
    )
    result = run_job_command(
      job,
      openscap_command,
      stage=ScanJob.Stage.RUNNING_OPENSCAP,
      progress_percent=97,
      message="Executing OpenSCAP benchmark evaluation.",
      sudo=True,
      timeout=3600,
    )
    if result.exit_status == 0:
      xml_text = download_text(job.server, f"{remote_dir}/oscap-results.xml") or ""
      html_text = download_text(job.server, f"{remote_dir}/oscap-report.html") or ""
      if xml_text:
        _save_text(job_dir / "oscap-results.xml", xml_text)
      if html_text:
        _save_text(job_dir / "oscap-report.html", html_text)
      if xml_text:
        findings_summary.update(_parse_openscap_results(job, xml_text, openscap_profile))
      else:
        findings_summary["openscap_error"] = 1
        scan_warnings.append("OpenSCAP did not produce results output.")
    else:
      findings_summary["openscap_error"] = 1
      scan_warnings.append("OpenSCAP benchmark evaluation did not complete successfully.")

  job.raw_output_path = str(job_dir)
  job.tools_used = tools_used
  job._scan_warnings = scan_warnings
  job.parsed_findings = [{"source": key, "count": value} for key, value in findings_summary.items()]


def execute_scan_job_pipeline(job):
  ensure_job_not_cancelled(job)
  with transaction.atomic():
    if job.queue_name == ScanJob.Queue.INSTALL:
      execute_install_job(job)
    elif job.queue_name == ScanJob.Queue.DISCOVERY:
      execute_discovery_job(job)
    else:
      execute_scan_job(job)

  warnings = list(getattr(job, "_scan_warnings", []))
  job.stage = ScanJob.Stage.COMPLETED
  job.status = ScanJob.Status.COMPLETED_WITH_WARNINGS if warnings else ScanJob.Status.COMPLETED
  job.progress_percent = 100
  job.current_command = ""
  job.ended_at = timezone.now()
  context = dict(job.progress_context or {})
  context["last_message"] = "Job completed with warnings." if warnings else "Job completed successfully."
  context["details"] = {
    "tools_used": job.tools_used,
    "artifact_path": job.raw_output_path,
    "finding_groups": len(job.parsed_findings or []),
    "warnings": warnings,
  }
  job.progress_context = context
  job.save(update_fields=["stage", "status", "progress_percent", "current_command", "progress_context", "ended_at", "raw_output_path", "tools_used", "parsed_findings", "updated_at"])