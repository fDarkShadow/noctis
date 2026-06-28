# noctis

**Rust vulnerability scanner driven by YAML feeds.**

Noctis detects CVEs and misconfigurations by running structured YAML test sequences against live services — no agent, no shared cache, no false-positive-prone version guessing. Each feed is a self-contained, reproducible detection unit.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-%3E%3D1.75-orange)](https://www.rust-lang.org)

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

## Requirements

| Dependency | Version | Purpose |
|------------|---------|---------|
| Rust | ≥ 1.75 | Build |
| pkg-config + libssl-dev | system | Build (libssh2 is vendored; OpenSSL headers needed at compile time) |
| Ansible-core | ≥ 2.15 | E2E tests only |
| Podman | ≥ 4.0 | E2E tests only |
| Docker + buildx | any | E2E tests only (mock image builds) |
| [Task](https://taskfile.dev) | ≥ 3.0 | E2E tests only |

---

## CLI reference

```sh
# Verbosity
noctis -v serve ...    # INFO
noctis -vv serve ...   # DEBUG

# OOB for blind detections (Log4Shell, SSRF)
noctis serve --oob --oob-host <public-ip> --oob-port 9090

# Docker
docker run -v ./tests:/feeds -p 8080:8080 noctis:ci serve --host 0.0.0.0 --port 8080
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
task test CVE=CVE-2021-41773    # true-positive + true-negative for one CVE
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

See [`CLAUDE.md`](CLAUDE.md) for the full authoring guide: feed conventions, Python mock template, inventory structure, known pitfalls, and reference feeds to copy from.

In short:
1. Write a feed in `tests/cve/` with a stable UUID v4 `uid`
2. Add a Podman mock in `infra/docker/` (HTTP:80 + HTTPS:443)
3. Add an inventory in `infra/inventories/` (4 hosts: vuln, vuln_https, patched, patched_https)
4. Add `infra/playbooks/10-<CVE>.yml` (auto-discovered) and a bake target in `infra/bake/<family>.hcl` (auto-discovered)
5. Run `task build && task test CVE=<your-cve>` — expect 4 passing tests

---

## License

MIT — see [LICENSE](LICENSE).
