# Changelog

## 0.1.0 - 2026-05-04

- Created the initial Django project scaffold under `app`
- Added split settings for base, development, and production
- Configured PostgreSQL via `.env`
- Added an email-based authentication model with role support
- Added domain apps for dashboard, servers, scanners, vulnerabilities, SBOMs, reports, and core settings
- Added a PostgreSQL-backed background worker command using `FOR UPDATE SKIP LOCKED`
- Added SSH-driven install, discovery, and scan execution pipeline code for Syft, Grype, and Trivy jobs
- Added HTMX-powered inline create and edit flows for servers and scan profiles
- Added HTMX-driven vulnerability triage updates on the finding detail page
- Added live HTMX polling for scan job tables and per-server activity panels
- Vendored HTMX and Alpine locally into `static/vendor/js` and removed their CDN usage from templates
- Added global live status cards and recent-job toast indicators using HTMX out-of-band polling updates
- Added `Run once now` scan actions on server and application rows with HTMX queueing
- Added per-job stage tracking for install, discovery, SBOM, Grype, Trivy, parsing, completion, and cancellation
- Added cancel and retry actions directly in the live jobs table
- Added structured job progress fields for percent complete, current command, and progress event history
- Added expandable job details and a dedicated job page for output previews and diagnostics
- Switched settings and entrypoints from `django-environ` to `python-dotenv`
- Added WhiteNoise compressed manifest static file handling for production
- Kept expanded job detail rows open across live table refreshes and added downloadable job artifact links
- Added Lynis and OpenSCAP support for Linux posture and benchmark-compliance scanning
- Added normalized compliance findings for Trivy misconfigurations and secrets plus Lynis and OpenSCAP results
- Added CNAPP coverage and standards alignment documentation
- Added shared `templates`, `static`, and `media` directories
- Added Tailwind CSS build configuration and a dark-mode security dashboard shell
- Added open-source project documentation and contribution guidance