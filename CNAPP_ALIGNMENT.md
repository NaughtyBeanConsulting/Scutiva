# Scutiva CNAPP Alignment

Scutiva is not yet a full commercial CNAPP, but it now covers several CNAPP building blocks in a unified workflow for Linux servers and discovered application paths.

## What Scutiva Covers Today

### Cloud Workload Protection Platform (CWPP)

- Server onboarding and SSH-based workload access
- VM and codebase scanning from a single queue-driven workflow
- SBOM generation with Syft
- Vulnerability correlation with Grype and Trivy
- Host hardening and posture review with Lynis
- Benchmark-based compliance evaluation with OpenSCAP

### Application Security and Software Composition Analysis

- Dependency and package discovery through application discovery jobs
- SBOM-backed software composition analysis using Syft and Grype
- Filesystem vulnerability, misconfiguration, and secret detection through Trivy

### Security Posture and Compliance

- OpenSCAP support for SCAP-compatible content and benchmark execution
- Lynis support for Linux hardening and operational posture checks
- Persisted compliance findings normalized into a first-class Scutiva model

### Unified Operations

- Shared job queue, progress tracking, artifact retention, and per-scan diagnostics
- Single UI for vulnerability findings, compliance findings, artifacts, and scan progress
- Downloadable raw artifacts for investigations and audit evidence

## What Scutiva Does Not Fully Cover Yet

### CSPM

- No direct AWS, Azure, GCP, or Kubernetes control-plane API integration yet
- No continuously refreshed cloud account posture graph

### CIEM

- No native entitlement analysis for IAM roles, policies, service principals, or trust relationships

### CDR and Runtime Protection

- No always-on runtime sensor, eBPF telemetry, or live workload blocking today
- No incident correlation graph across identities, workloads, network paths, and data stores

### Security Graph and Prioritization

- Scutiva aggregates findings, but it does not yet build a Wiz-style attack path graph or blast-radius engine

## Standards Scutiva Should Follow

To align with international and widely adopted security standards, Scutiva should treat these as implementation targets:

- SCAP, XCCDF, OVAL, and CPE for host compliance and benchmark execution
- CIS Benchmarks for Linux hardening guidance
- NIST SP 800-53 and NIST SP 800-190 as control-mapping references for container and cloud-native security
- CVE, CVSS, and CISA KEV for vulnerability identification and prioritization
- SPDX and CycloneDX for portable SBOM exchange
- SARIF for static-analysis and code-scan interoperability
- OpenTelemetry for event and runtime telemetry normalization
- Open Policy Agent and Rego for policy-as-code enforcement

## Practical Next Steps To Move Closer To A CNAPP

1. Add cloud-provider collectors for AWS, Azure, and GCP posture data.
2. Add IAM and entitlement inventory to cover CIEM.
3. Add policy-as-code checks with OPA or Conftest for infrastructure and deployment controls.
4. Add runtime telemetry with Falco, Wazuh, or osquery for Linux workload detection.
5. Add graph correlation between vulnerabilities, misconfigurations, secrets, identities, and exposed services.
6. Add standards-grade export formats such as CycloneDX, SPDX, and SARIF.
7. Add benchmark-to-control mapping views for CIS, NIST, ISO 27001, and SOC 2 evidence generation.