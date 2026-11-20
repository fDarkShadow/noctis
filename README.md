<p align="center">
  <img src="assets/noctis-logo.png" alt="noctis" width="420">
</p>

<h1 align="center">noctis — Rust vulnerability scanner driven by YAML feeds</h1>

Noctis detects CVEs and misconfigurations by running structured YAML test sequences against live services — no agent, no shared cache, no false-positive-prone version guessing. Each feed is a self-contained, reproducible detection unit.

[![CI](https://github.com/fDarkShadow/noctis/actions/workflows/ci.yml/badge.svg)](https://github.com/fDarkShadow/noctis/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-%3E%3D1.75-orange)](https://www.rust-lang.org)
[![Docker](https://ghcr-badge.egpl.dev/fdarkShadow/noctis/size?tag=edge&label=image)](https://github.com/fDarkShadow/noctis/pkgs/container/noctis)

---

## Demo

<!-- Replace with an asciinema cast or a GIF showing a scan from POST /scans to a finding.
     Example: [![asciicast](https://asciinema.org/a/XXXXXX.svg)](https://asciinema.org/a/XXXXXX) -->
<p align="center"><em>Demo coming soon — until then, see <a href="#quick-start">Quick start</a>.</em></p>

---

## Why noctis?

Most network vulnerability scanners either **guess from version banners** (noisy and
false-positive-prone) or bury detection logic in compiled code. noctis takes a different path:

- **Proof over guessing** — a finding is raised only when a step *observes* the vulnerable
  behaviour (an LFI response, an unauthenticated reply, an out-of-band callback), and each is
  graded with an OpenVAS-style Quality-of-Detection (QoD) score.
- **Detection as data** — every check is a self-contained YAML feed, not compiled code. Read it,
  audit it, or write your own in minutes.
- **No agent, no shared state** — point it at live services over the network; each feed is
  standalone and reproducible.
- **Rust single binary** — fast, memory-safe, with a REST API for automation and CI/CD.

If you've used **Nuclei** or **OpenVAS**: noctis sits between them — data-driven feeds like the
former, evidence-graded findings like the latter.

| | Version-based scanners | Template scanners | **noctis** |
|---|---|---|---|
| Detection logic | code / CPE match | templates | **YAML feeds** |
| Evidence-graded findings | partial | varies | **yes (QoD)** |
| Blind / OOB detection | rarely | varies | **built-in callback server** |
| Raw-TCP payloads (no URL normalisation) | rarely | varies | **yes** |
| Runtime | varies | Go | **Rust (single binary)** |

---

## Use cases

- **DevSecOps / CI-CD** — run `noctis serve` and submit scans from a pipeline over the REST API;
  gate releases on findings.
- **Pentest & red team** — fast, evidence-based black-box checks against live targets with no
  prior knowledge of the infrastructure.
- **Continuous exposure monitoring** — surface misconfigurations (open databases, unauthenticated
  services, weak TLS) across a fleet.
- **Custom detections** — express an in-house check as a YAML feed without touching the engine.

---

## Features

- **YAML feeds** — one file per CVE or misconfig; declare steps, patterns, and confidence deltas
- **Service-aware** — feeds declare target services (`http`, `https`, `ssh`…); the engine maps them to discovered ports
- **Raw TCP** — `tcp_connect` sends bytes verbatim for encoded payloads (path traversal, injections), bypassing HTTP normalisation
- **Graduated confidence** — each finding carries a QoD score (OpenVAS-compatible)
- **OOB detection** — built-in HTTP callback server for blind detections (Log4Shell, SSRF, XXE)
- **Protocols** — HTTP/HTTPS (reqwest), raw TCP, TLS (rustls), SSH (libssh2)
- **REST API** — `noctis serve` exposes scan submission, status polling, and findings retrieval
- **Reproducible tests** — Ansible + rootless Podman, dynamic port allocation, automated TP/TN assertions

---

## Quick start

```sh
# Build
git clone https://github.com/fDarkShadow/noctis
cd noctis
cargo build --release

# Start the daemon
./target/release/noctis serve --host 0.0.0.0 --port 8080

# Submit a scan (REST API)
curl -s -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "host": "10.0.0.1",
    "services": [
      {"port": 80,  "service": "http",  "protocol": "tcp"},
      {"port": 443, "service": "https", "protocol": "tcp"}
    ],
    "tests": ["tests/cve/"],
    "concurrency": 10
  }' | jq .

# Poll for results
curl -s http://localhost:8080/scans/<id>/findings | jq .
```

Findings response:

```json
[
  {
    "type": "cve",
    "cve_id": "CVE-2021-41773",
    "severity": "critical",
    "confidence": 0.95,
    "qod": 75,
    "evidence": {
      "response_excerpt": "LFI confirmed — /etc/passwd readable via path traversal"
    }
  }
]
```

---

## Run with Docker

Prebuilt images are published to the **GitHub Container Registry (GHCR)** as a minimal
`scratch` image (a static musl binary — no shell, a few MB), for **`linux/amd64`** and
**`linux/arm64`**.

```sh
# Pull the latest release
docker pull ghcr.io/fdarkshadow/noctis:latest

# Run the daemon — mount your feeds at /feeds
docker run --rm -v ./tests:/feeds -p 8080:8080 \
  ghcr.io/fdarkshadow/noctis serve --host 0.0.0.0 --port 8080
```

**Tags:**

| Tag | Points to |
|-----|-----------|
| `latest` | the most recent release |
| `X.Y.Z` / `X.Y` | a specific released version |
| `edge` | the latest commit on `main` |

Images are published automatically: `:edge` on every push to `main`, and the versioned
`:X.Y.Z` / `:latest` tags when a `vX.Y.Z` release is tagged. See all tags on the
[package page](https://github.com/fDarkShadow/noctis/pkgs/container/noctis).

---

## Requirements

| Dependency | Version | Purpose |
|------------|---------|---------|
| Rust | ≥ 1.75 | Build |
| pkg-config + libssl-dev | system | Build (libssh2 is vendored; OpenSSL headers needed at compile time) |
| Ansible-core | ≥ 2.15 | E2E tests only |
| Podman | ≥ 4.0 | E2E tests only (build + run) |
| [Task](https://taskfile.dev) | ≥ 3.0 | E2E tests only |

---

## CLI reference

```sh
# Verbosity
noctis -v serve ...    # INFO
noctis -vv serve ...   # DEBUG

# OOB for blind detections (Log4Shell, SSRF)
noctis serve --oob --oob-host <public-ip> --oob-port 9090

# Docker (see "Run with Docker" above)
docker run -v ./tests:/feeds -p 8080:8080 ghcr.io/fdarkshadow/noctis:latest serve --host 0.0.0.0 --port 8080
```

```sh
noctis serve --host 0.0.0.0 --port 8080
```

| Method | Route | Description |
|--------|-------|-------------|
| `GET` | `/health` | Healthcheck |
| `POST` | `/scans` | Submit a scan |
| `GET` | `/scans` | List scans |
| `GET` | `/scans/{id}` | Scan status |
| `DELETE` | `/scans/{id}` | Cancel a scan |
| `GET` | `/scans/{id}/findings` | Findings for a scan |

**POST /scans body:**

```json
{
  "host": "10.0.0.1",
  "services": [
    { "port": 80,  "service": "http",  "protocol": "tcp" },
    { "port": 443, "service": "https", "protocol": "tcp" }
  ],
  "tests": ["tests/cve/", "tests/misconfig/"],
  "concurrency": 10
}
```

---

## Available feeds

CVE feeds live in [`tests/cve/`](tests/cve/) — one YAML file per CVE. Coverage includes
critical vulnerabilities across Apache, Atlassian, F5, Fortinet, GitLab, Ivanti, Jenkins,
Microsoft Exchange, OpenSSH, PHP, Pulse Secure, VMware, and more.

Misconfiguration checks live in [`tests/misconfig/`](tests/misconfig/): exposed paths,
missing HTTP security headers, weak SSH auth, and weak TLS configuration.

---

## YAML feed format

A feed is a YAML file describing metadata and a sequence of steps. Steps build up confidence toward a finding.

```yaml
uid: a3c7f4e2-1b9d-4f6a-8e3c-2d5a0f1e9b4c   # stable UUID v4 — never change
name: "Apache httpd 2.4.49 Path Traversal / RCE (CVE-2021-41773)"
type: cve                   # cve | misconfig
cve: CVE-2021-41773
cvss: 9.8
severity: critical          # info | low | medium | high | critical
confidence_base: 0.30
tags: [apache, path-traversal, rce]
services: [http, https]     # nmap service names — empty = all ports
author: noctis
version: "1.0.0"

steps:
  - id: probe
    action: tcp_connect      # raw TCP — payload sent verbatim
    port: "{{port}}"
    send: "GET /icons/.%2e/.%2e/etc/passwd HTTP/1.0\r\nHost: {{target_host}}\r\n\r\n"
    store_as: resp

  - id: match
    action: match
    source: resp.banner      # always .banner on tcp_connect results
    pattern: "root:[x*!]:0:0"
    on_match:
      finding:
        confidence_delta: 0.65
        qod: 75
        evidence: "LFI confirmed — /etc/passwd readable"
      stop: true
```

### Automatic variables

| Variable | Value |
|----------|-------|
| `{{target_host}}` | Target IP / hostname |
| `{{port}}` | Port of the matched service (injected by engine — do not redefine) |
| `{{scheme}}` | `http` or `https` — derived from the matched service name |
| `{{oob_token}}` | UUID unique to this run |
| `{{oob_url}}` | Full OOB callback URL |
| `{{oob_host}}` | OOB server host |
| `{{oob_port}}` | OOB server port |
| `{{oob_enabled}}` | `true` when `--oob` is configured |

### Available actions

| Action | Description |
|--------|-------------|
| `http_request` | HTTP/HTTPS request (reqwest); result fields: `resp.status`, `resp.body`, `resp.headers` |
| `tcp_connect` | Raw TCP socket + banner grab; result field: `resp.banner` |
| `tls_check` | TLS version, cipher, certificate inspection |
| `ssh_check` | SSH banner + auth methods; result fields: `resp.banner`, `resp.auth_methods` |
| `match` | Regex match on a context variable |
| `script` | Arbitrary [Rhai](https://rhai.rs) script |
| `wait_oob` | Wait for OOB HTTP callback |
| `set_var` | Assign a context variable |

### Confidence / QoD scale

| QoD | Meaning |
|-----|---------|
| 50 | Banner or version match |
| 70 | Specific header / response pattern |
| 75 | Functional proof (LFI `/etc/passwd`, known-good response body) |
| 97 | OOB callback received, or confirmed RCE |
| 100 | Full exploit with verified output |

### `tcp_connect` vs `http_request`

Use `tcp_connect` for any payload encoded in the path — reqwest normalises URLs before sending (`%2e` → `.` then resolves `../`), which breaks path traversal exploits.

```yaml
# Correct — verbatim bytes, no normalisation
- action: tcp_connect
  send: "GET /cgi-bin/.%2e/.%2e/etc/passwd HTTP/1.0\r\nHost: {{target_host}}\r\n\r\n"
  store_as: resp

- action: match
  source: resp.banner    # .banner, not .data
  pattern: "root:.*:0:0"
```

Feed validation is available via JSON Schema:

```sh
npx ajv-cli validate -s schemas/feed.schema.json \
  -d "tests/cve/*.yaml" --spec=draft7 --allow-union-types
```

The Red Hat YAML VS Code extension picks up the schema automatically via `.vscode/settings.json`.

---

## Test infrastructure

End-to-end tests use Ansible + rootless Podman. Two `noctis serve` instances start once for the suite — one plain, one with OOB — and tests submit scans via the REST API (`POST /scans`).

```sh
cd infra

task build          # build all mock images in parallel (docker buildx bake)
task test ID=CVE-2021-41773     # true-positive + true-negative for one CVE
task test-all       # all CVEs — servers start once, all inventories in one run
task check-deps     # verify prerequisites
```

Each CVE test covers four cases: `vuln` (HTTP), `vuln_https`, `patched` (HTTP), `patched_https`.

Playbooks are auto-discovered by sorted filename: `00-build-mocks` → `00-build-noctis` → `01-start-servers` → `10-CVE-*` → `99-stop-servers`.

For full details on adding feeds and writing mocks, see [`CLAUDE.md`](CLAUDE.md).

---

## Performance

At default concurrency (`--concurrency 5`) and 10s step timeout, a scan of 50 services against 300 feeds generates roughly 4 000 tasks. Expected wall-clock time:

| Concurrency | Local network | Remote / WAN |
|-------------|--------------|--------------|
| 5 (default) | 10–20 min | 20–40 min |
| 20 | 3–6 min | 8–15 min |
| 50 | 1–3 min | 3–8 min |

Most of the time is spent on step timeouts for non-matching services. Increase `--concurrency` and reduce `timeout_secs` in feeds to speed up large scans.

---

## Contributing

Contributions are welcome! Start with **[CONTRIBUTING.md](CONTRIBUTING.md)** — it covers the dev
setup, design principles, and the step-by-step workflow for adding a detection feed or an engine
capability. [`CLAUDE.md`](CLAUDE.md) holds the deep authoring reference (conventions, mock
template, inventory structure, pitfalls, and reference feeds to copy from).

Please also read our [Code of Conduct](CODE_OF_CONDUCT.md). To report a security issue in noctis
itself, follow [SECURITY.md](SECURITY.md) — **do not open a public issue**.

---

## License

MIT — see [LICENSE](LICENSE).
