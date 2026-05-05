# Changelog

## 0.1.0 - 2026-05-04

### Platform foundation

- Bootstrapped the Scutiva Django application under `app` with split settings modules for `base`, `development`, and `production`.
- Standardized configuration loading on `python-dotenv` and `.env` instead of `django-environ`, including updates to `manage.py`, `wsgi.py`, `asgi.py`, and `app.settings` loading.
- Configured PostgreSQL as both the primary application datastore and the job queue backing store.
- Added WhiteNoise compressed manifest storage for production static asset serving.
- Established the application domains for `accounts`, `dashboard`, `servers`, `scanners`, `vulnerabilities`, `sboms`, `reports`, and `core`.
- Added shared `templates`, `static`, and `media` directories and aligned the project structure around a production-oriented Django layout.

### Authentication and operator access

- Added a custom email-based authentication model and login flow instead of username-based authentication.
- Implemented the base operator workflow for authenticated access to dashboard, server onboarding, scanning, and finding review features.

### Frontend delivery and operator UX

- Added Tailwind CSS build tooling and compiled local CSS assets for the Scutiva dashboard UI.
- Vendored HTMX and Alpine.js into `static/vendor/js` and removed CDN runtime dependencies.
- Implemented HTMX-powered inline create and edit flows for server onboarding and scan profile management.
- Added HTMX-driven live polling for scan jobs, per-server activity panels, live status summaries, and recent-job notifications.
- Added `Run once now` actions on server and application surfaces to reduce operator friction when queueing scans.
- Added expandable job detail rows and a dedicated scan job detail page for diagnostics, artifact previews, parsed summaries, and operator troubleshooting.
- Kept expanded detail rows stable across HTMX refresh cycles so live polling does not collapse in-progress inspection state.

### Queueing and execution architecture

- Implemented PostgreSQL-backed background execution using `FOR UPDATE SKIP LOCKED` rather than Redis or Celery.
- Added the `run_scan_worker` management command to claim queued jobs safely and process them with row-level locking semantics.
- Added structured job lifecycle state for queueing, claiming, install, discovery, SBOM generation, Grype execution, Trivy execution, Lynis execution, parsing, completion, failure, and cancellation.
- Added structured job progress fields for percentage completion, current remote command, and an append-only event history suitable for UI polling and post-run diagnostics.
- Added cancellation and retry flows directly on queued or running jobs, with worker-side cancellation handling and terminal job-state normalization.
- Added scheduled profile dispatch backed by PostgreSQL with deduplication windows for daily, weekly, and monthly scan profiles.
- Added `schedule_scan_jobs` as a management command to enqueue due scheduled scans without introducing an external scheduler dependency into the app itself.

### SSH-based remote execution model

- Implemented an agentless remote execution model: Scutiva is the orchestrator and executes all install, discovery, and scan tasks over SSH.
- Added encrypted at-rest storage for server credentials, including password, private key, and optional sudo password.
- Added Paramiko-backed SSH helpers for command execution, file upload, and file download.
- Hardened SSH connectivity with configurable connection timeout, banner timeout, authentication timeout, retry count, and retry delay.
- Added remote temporary file and directory cleanup after install and scan execution to avoid leaving stale artifacts on target hosts.
- Added host key fingerprint capture during onboarding and strict fingerprint verification for production servers.
- Enforced pinned host-key verification on later SSH sessions for production hosts so they do not rely on trust-on-first-use in steady state.

### Server onboarding and remote installation

- Implemented server onboarding with SSH credentials, environment classification, discovery root configuration, and connection testing.
- Added scanner installation tracking per server through `ScannerInstallation` status and version metadata.
- Added a generated Ubuntu-first remote installer script to prepare the target host for Scutiva-managed scans.
- Added explicit portal actions for `Install on server` and `Queue discovery` so onboarding is driven from Scutiva rather than manual shell steps.
- Added installed-version collection for the retained scanner toolchain after remote installation completes.

### Discovery and targeting

- Added remote discovery of likely application roots by scanning configured directories for dependency manifests and common project markers.
- Added persistence of discovered applications, framework hints, language hints, dependency files, and container-related markers.
- Added server-level and application-level scan targeting so operators can scan a whole host or a specific discovered application path.

### Scanning scope and retained layers

- Narrowed the Scutiva scanning scope to the implemented layers that matter now:
    - VM / OS posture layer
    - Package / SBOM / vulnerability layer
- Explicitly excluded broader runtime telemetry, HIDS, and embedded SAST integrations from the current product implementation.
- Kept SonarQube as an external code-analysis system rather than embedding Semgrep or Bandit into the Scutiva worker.

### Retained scanner toolchain

- Standardized the current Scutiva scanner stack on four tools only:
    - `Lynis`
    - `Syft`
    - `Grype`
    - `Trivy`
- Removed OpenSCAP and other previously considered tools from the implemented path to keep the execution model focused and operationally manageable.

### Layer 1: VM / OS posture and host hardening

- Added `Lynis` execution for lightweight Linux host posture and hardening review.
- Added Lynis stage tracking in the worker pipeline and persisted Lynis output artifacts into the job media directory.
- Parsed Lynis findings into normalized compliance-style records so host-hardening issues appear inside the same Scutiva review surfaces as other security signals.
- Positioned this layer as the current VM / OS coverage for Ubuntu and Linux hosts rather than implementing full benchmark-engine complexity.

### Layer 2: Package inventory, SBOM generation, and CVE detection

- Added `Syft` execution to generate SBOM JSON for the selected target path on the remote host.
- Persisted Syft-generated SBOM artifacts locally in Scutiva for later inspection and reuse.
- Added `Grype` execution against the generated SBOM to perform vulnerability correlation on enumerated packages.
- Added `Trivy` filesystem scanning as a broader shortcut path over the target directory.
- Configured Trivy to scan for vulnerabilities, misconfigurations, secrets, and license-related signals in a single filesystem pass.
- Parsed Grype and Trivy output into normalized finding records so package-layer results can be reviewed consistently in Scutiva.

### Finding normalization and persistence

- Added normalization and persistence for vulnerability findings derived from Grype and Trivy.
- Added `ComplianceFinding` for posture and misconfiguration-style results so non-CVE signals are treated as first-class data.
- Added normalized persistence for Trivy misconfigurations and secrets plus Lynis findings.
- Added artifact download support and raw output previews from the media-backed job directories for operator verification and debugging.

### Dashboard and review workflow

- Added dashboard summaries for queue health, recent outcomes, and normalized posture counts.
- Added live operator feedback for active jobs and recent failures through HTMX-driven status widgets and notifications.
- Added vulnerability triage interaction on finding detail surfaces.
- Added detailed scan job diagnostics including raw outputs, parsed summaries, structured progress context, and job history events.

### Documentation and technical positioning

- Added and updated technical documentation covering setup, scanning flow, scheduling flow, and CNAPP-adjacent product positioning.
- Documented the actual implemented result flow: Scutiva queues the job, the worker claims it, connects by SSH, executes remotely, downloads artifacts, parses locally, and persists results in PostgreSQL and `media/`.
- Documented the current engineering scope as an agentless, SSH-orchestrated scanning platform rather than a runtime agent platform.
- Updated roadmap and alignment documentation to reflect the retained four-tool model and the current focus on VM / OS posture plus package / CVE coverage.

### Scope decisions and removals

- Removed OpenSCAP support from the active scanner model, forms, admin, pipeline stages, installation flow, and documentation.
- Explicitly left Falco, Wazuh, Semgrep, and Bandit out of the implemented Scutiva runtime and worker pipeline.
- Chose architectural simplicity over breadth by keeping the scanning path agentless, SSH-driven, and PostgreSQL-queued.