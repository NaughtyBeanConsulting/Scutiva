# Scutiva

Scutiva is an open-source Django portal for scanning remote Linux servers and application codebases for CVEs. It focuses on practical security operations for small teams: onboard SSH servers, discover application paths, generate SBOMs with Syft, compare findings from Grype and Trivy, and review results in a dark-mode dashboard.

## Stack

- Django with split settings for base, development, and production
- `python-dotenv` for `.env` loading across `manage.py`, WSGI, ASGI, and the settings package
- HTMX and Alpine.js for interactive UI behavior
- Tailwind CSS for the dashboard theme
- PostgreSQL for the main data store and the background job queue
- WhiteNoise for static asset serving in production
- Paramiko for SSH connectivity
- Syft, Grype, Trivy, Lynis, and OpenSCAP for scanning and host posture assessment

## Project layout

```text
Scutiva/
├── accounts/
├── app/
│   └── settings/
│       ├── base.py
│       ├── development.py
│       └── production.py
├── core/
├── dashboard/
├── media/
├── reports/
├── sboms/
├── scanners/
├── servers/
├── static/
├── static_src/
├── templates/
└── vulnerabilities/
```

## Getting started

1. Create PostgreSQL locally and ensure the database in `.env` exists.
2. Create and activate the virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install Python dependencies:

```bash
pip install -r requirements.txt
```

4. Install frontend dependencies and build the Tailwind CSS bundle:

```bash
npm install
npm run build:css
```

5. Review `.env` and confirm the development database settings:

```dotenv
DB_NAME=scutiva
DB_USER=postgres
DB_PASSWORD=admin
DB_HOST=127.0.0.1
DB_PORT=5432
```

6. Create migrations and apply them:

```bash
python manage.py makemigrations
python manage.py migrate
```

7. Create an admin user using email-based authentication:

```bash
python manage.py createsuperuser
```

8. Start the Django dev server:

```bash
python manage.py runserver
```

9. In a second shell, run the PostgreSQL-backed worker loop:

```bash
source venv/bin/activate
python manage.py run_scan_worker
```

The default entrypoints now target `app.settings`, which auto-selects development or production based on `DEBUG` after loading `.env`.

## Background jobs with PostgreSQL

Scutiva does not depend on Redis. Queued scan jobs are claimed directly from PostgreSQL using `FOR UPDATE SKIP LOCKED`, which allows multiple workers to compete safely without processing the same job twice.

The worker implementation lives in `scanners/management/commands/run_scan_worker.py`, and queued jobs are claimed through `ScanJob.objects.claim_next()`.

## Development notes

- Shared templates live in `templates/`
- Shared static assets live in `static/`
- Uploaded files live in `media/`
- The login system uses email and password, not usernames
- SSH secrets are encrypted at rest using the application field encryption key in `.env`
- Tailwind is compiled locally with `npm run build:css` into `static/css/app.css`; the project does not use the Tailwind CDN
- HTMX and Alpine are vendored locally with `npm run build:vendor` into `static/vendor/js/`
- Static files use WhiteNoise with compressed manifest storage in production
- Server management, scan profile management, and finding triage now use HTMX partial flows for inline updates
- Scan workers execute install, discovery, and scan jobs directly from PostgreSQL queue rows using `SKIP LOCKED`
- Global live status cards and recent-job toasts poll every 5 seconds via HTMX OOB swaps
- Server and application tables provide `Run once now` HTMX actions that queue scans and prefill the queue form
- Jobs expose per-stage progress such as install, discovery, SBOM build, Grype, Trivy, and parsing
- Live jobs can be cancelled while queued or running, and failed/cancelled/warning jobs can be retried from the table
- Jobs persist percentage progress, the current remote command, and a structured event history for each execution
- Each job now has an expandable detail panel and a dedicated detail page for logs, output previews, parsed findings, downloadable artifacts, and failure diagnostics
- Expanded job rows stay open across the 5-second live table refresh cycle
- Trivy scans filesystem targets for vulnerabilities, misconfigurations, secrets, and license signals
- Lynis and OpenSCAP add Linux hardening and benchmark-compliance coverage for Ubuntu servers

## CNAPP alignment

Scutiva now spans several CNAPP-adjacent domains in one workflow: workload scanning, software composition analysis, host posture review, benchmark compliance, and consolidated findings review. It still does not replace a full commercial CNAPP because it lacks native multi-cloud CSPM, CIEM, runtime sensors, and graph-based attack-path prioritization.

For a detailed coverage and standards map, see [CNAPP_ALIGNMENT.md](CNAPP_ALIGNMENT.md).

## Next implementation steps

- Replace the placeholder worker execution with real Syft, Grype, and Trivy orchestration.
- Add JSON/CSV/HTML report generation.
- Extend HTMX polling for real-time scan progress and live status updates.
