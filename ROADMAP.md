# Scutiva Roadmap

Scutiva is intentionally focused on four layers for now: SSH-based server onboarding, agentless Ubuntu tool installation, host posture checks with Lynis, and package or filesystem vulnerability analysis with Syft, Grype, and Trivy.

## Active coverage

### VM / OS layer
- Lynis runs a fast Linux hardening audit over SSH.
- Trivy contributes misconfiguration, secret, and license signals during filesystem scans.

### Package / CVE layer
- Syft generates the SBOM for the selected target.
- Grype scans the SBOM for vulnerable packages.
- Trivy provides a broad filesystem-first shortcut scan.

## Portal workflow

1. Add a server with SSH credentials.
2. Click `Install on server` in the Scutiva portal.
3. Scutiva uploads and runs the Ubuntu installer remotely with sudo.
4. The installer prepares Lynis, Syft, Grype, and Trivy on the VM.
5. Queue discovery or queue scans directly from the portal.
6. For recurring work, set a scan profile to `Daily`, `Weekly`, or `Monthly` and run `python manage.py schedule_scan_jobs` from cron or a systemd timer on the Scutiva host.

## Result flow

1. Scutiva creates a PostgreSQL-backed `ScanJob`.
2. `run_scan_worker` claims the job with `FOR UPDATE SKIP LOCKED`.
3. The worker connects to the remote Ubuntu server over SSH.
4. Raw outputs are downloaded back into `media/scan_jobs/`.
5. Scutiva parses the results and stores findings in PostgreSQL for the dashboard, job detail pages, and exports.

## Out of scope for now

- OpenSCAP
- Semgrep
- Bandit
- Falco
- Wazuh
- Embedded SonarQube execution

SonarQube remains an external code-scanning system rather than a built-in Scutiva worker tool.

