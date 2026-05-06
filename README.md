# Scutiva

<p align="center">
	<picture>
		<source media="(prefers-color-scheme: light)" srcset="static/img/ScutivaWhite1024x1024.png">
		<source media="(prefers-color-scheme: dark)" srcset="static/img/Scutiva1024x1024.png">
		<img src="static/img/Scutiva1024x1024.png" alt="Scutiva logo" width="180">
	</picture>
</p>

Scutiva is an open-source, self-hosted security operations portal for Linux hosts and application codebases. It uses an agentless SSH execution model to onboard servers, install its toolchain remotely, generate SBOMs, correlate package vulnerabilities, run Linux posture checks, and review findings in a live operator workflow.

## Why Scutiva

- Open source under the MIT license
- Self-hosted only, with no hosted Scutiva control plane
- Agentless remote execution over SSH
- PostgreSQL-backed worker queue using `FOR UPDATE SKIP LOCKED`
- Focused scanning coverage built around four retained tools: `Lynis`, `Syft`, `Grype`, and `Trivy`

## Current scanning layers

Scutiva uses four retained tools across its scanning flow: `Lynis`, `Syft`, `Grype`, and `Trivy`.

### VM / OS posture and host hardening

Scutiva uses `Lynis` to perform lightweight Linux posture and hardening reviews on onboarded Ubuntu and Linux hosts.

### Package / SBOM / CVE analysis

Scutiva uses:

- `Lynis` to complement package and SBOM review with Linux posture and hardening coverage
- `Syft` to generate SBOM artifacts
- `Grype` to correlate package vulnerabilities from the generated SBOM
- `Trivy` to scan filesystem targets for vulnerabilities, misconfigurations, secrets, and license signals

## Execution model

Scutiva is intentionally agentless.

1. Add a server with SSH credentials.
2. Test and pin the SSH host fingerprint during onboarding.
3. Click `Install on server` to upload and run the remote Ubuntu installer.
4. Queue discovery to map likely application roots.
5. Queue a manual scan, or dispatch scheduled scans through the PostgreSQL-backed scheduler command.
6. The worker claims queued rows with `FOR UPDATE SKIP LOCKED`, connects over SSH, executes the tools remotely, downloads artifacts, parses locally, and stores findings in PostgreSQL and `media/`.

## Core stack

- Django with split settings for base, development, and production
- `python-dotenv` for environment loading
- PostgreSQL for both data storage and background queueing
- Paramiko for SSH transport
- HTMX and Alpine.js for operator interactions
- Tailwind CSS for the UI layer
- WhiteNoise for production static file serving

## What Scutiva does not try to be

Scutiva is not currently trying to be a full hosted CNAPP or a broad runtime-agent platform.

The implemented scope deliberately excludes:

- OpenSCAP
- Falco
- Wazuh
- Semgrep
- Bandit

SonarQube is treated as an external code-analysis system rather than a built-in Scutiva scanner.

## Getting started

1. Create the PostgreSQL database referenced in `.env`.
2. Create and activate a virtual environment.

```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install Python dependencies.

```bash
pip install -r requirements.txt
```

4. Install frontend dependencies and compile the UI assets.

```bash
npm install
npm run build:css
```

5. Apply migrations.

```bash
python manage.py migrate
```

6. Create an admin user.

```bash
python manage.py createsuperuser
```

7. Start the web app and worker.

```bash
python manage.py runserver
python manage.py run_scan_worker
```

8. If you want recurring scans, dispatch scheduled profiles with:

```bash
python manage.py schedule_scan_jobs
```

## Development notes

- Shared templates live in `templates/`
- Shared static assets live in `static/`
- Uploaded files and scanner artifacts live in `media/`
- SSH secrets are encrypted at rest using the application field encryption key
- The server install flow uploads and executes an Ubuntu-first installer over SSH
- Production servers require a pinned SSH host fingerprint
- Jobs expose structured progress, stage tracking, remote command visibility, artifacts, and retry/cancel controls

## Documentation

- Technical standards and CNAPP-adjacent positioning: [CNAPP_ALIGNMENT.md](CNAPP_ALIGNMENT.md)
- Implementation history: [CHANGELOG.md](CHANGELOG.md)

## Project links

- GitHub: https://github.com/NaughtyBeanConsulting/Scutiva
- LinkedIn: https://linkedin.com/company/scutiva-oss
- Support Scutiva: https://donations.scutiva.com
- Contact: hello@scutiva.com
