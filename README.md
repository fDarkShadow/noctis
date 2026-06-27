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

# Scan a host — HTTP on port 80, HTTPS on 443, all CVE feeds
./target/release/noctis scan \
  --host 10.0.0.1 \
  --service http:80 \
  --service https:443 \
  --tests tests/cve/

# Single feed
./target/release/noctis scan \
  --host 10.0.0.1 \
  --service http:80 \
  --tests tests/cve/CVE-2021-41773.yaml
```

Output is JSON on stdout:

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "target": "10.0.0.1",
  "findings": [
    {
      "test_id": "a3c7f4e2-1b9d-4f6a-8e3c-2d5a0f1e9b4c",
      "cve": "CVE-2021-41773",
      "severity": "critical",
      "confidence": 0.95,
      "qod": 75,
      "evidence": "LFI confirmed — /etc/passwd readable via path traversal"
    }
  ]
}
```

Exit code `0` always (even with findings); `1` on execution error.

---

## Requirements

| Dependency | Version | Purpose |
|------------|---------|---------|
| Rust | ≥ 1.75 | Build |
| libssh2 + pkg-config | system | SSH checks |
| Ansible-core | ≥ 2.15 | E2E tests only |
| Podman | ≥ 4.0 | E2E tests only |
| [Task](https://taskfile.dev) | ≥ 3.0 | E2E tests only |

---

## CLI reference

```sh
# Verbosity
noctis -v scan ...    # INFO
noctis -vv scan ...   # DEBUG

# Concurrency (default: 5)
noctis scan --concurrency 20 ...

# OOB for blind detections (Log4Shell, SSRF)
noctis serve --oob --oob-host <public-ip> --oob-port 9090
```

### Daemon mode

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

### CVE detections

| CVE | Product | Severity | Detection |
|-----|---------|----------|-----------|
| CVE-2014-6271 | GNU Bash (Shellshock) | Critical | HTTP CGI header injection + RCE proof |
| CVE-2017-9841 | PHPUnit | Critical | `eval-stdin.php` + MD5 RCE proof |
| CVE-2019-11510 | Pulse Connect Secure | Critical | `%2F` path traversal → `/etc/passwd` |
| CVE-2021-21985 | VMware vCenter | Critical | vSAN pre-auth RCE endpoint |
| CVE-2021-22205 | GitLab CE/EE | Critical | ExifTool pre-auth RCE |
| CVE-2021-26855 | Microsoft Exchange | Critical | ProxyLogon SSRF → `X-CalculatedBETarget` |
| CVE-2021-41773 | Apache httpd 2.4.49 | Critical | LFI `/icons/` + RCE via mod_cgi |
| CVE-2021-43798 | Grafana | High | Plugin path traversal → `/etc/passwd` |
| CVE-2021-44228 | Log4j2 (Log4Shell) | Critical | `pom.properties` version (QoD 75) + OOB JNDI (QoD 97) |
| CVE-2022-1388 | F5 BIG-IP | Critical | iControl REST auth bypass |
| CVE-2022-22965 | Spring Framework | Critical | Spring4Shell ClassLoader RCE |
| CVE-2022-26134 | Atlassian Confluence | Critical | OGNL injection RCE |
| CVE-2023-22527 | Atlassian Confluence | Critical | SSTI/OGNL injection RCE |
| CVE-2023-34960 | Chamilo LMS | Critical | SOAP `wsConvertPpt` command injection |
| CVE-2023-46805 | Ivanti Connect Secure | High | REST API auth bypass (path traversal) |
| CVE-2023-48795 | OpenSSH / SSH servers | Medium | Terrapin — ChaCha20-Poly1305 negotiation |
| CVE-2023-49103 | ownCloud Graph API | High | `phpinfo()` exposure → credentials |
| CVE-2023-7028 | GitLab CE/EE | High | Account takeover via password reset injection |
| CVE-2024-21887 | Ivanti Connect Secure | Critical | Command injection RCE |
| CVE-2024-21893 | Ivanti Connect Secure | High | SAML SSRF |
| CVE-2024-4577 | PHP-CGI | Critical | Argument injection RCE |
| CVE-2024-55591 | Fortinet FortiOS/FortiProxy | Critical | Node.js WebSocket auth bypass |
| CVE-2024-6387 | OpenSSH (regreSSHion) | High | Pre-auth RCE — banner version |

### Misconfiguration checks

| Feed | Detection |
|------|-----------|
| `exposed-paths.yaml` | Sensitive paths accessible (`.git`, `.env`, `actuator`, etc.) |
| `http-security-headers.yaml` | Missing `X-Frame-Options`, `CSP`, `HSTS`, etc. |
| `ssh-weak-auth.yaml` | Password authentication enabled |
| `tls-weak-config.yaml` | TLS 1.0/1.1, RC4, export ciphers, self-signed certs |

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

End-to-end tests use Ansible + rootless Podman. Each CVE has a vulnerable and a patched container; the role starts them, runs `noctis scan`, and asserts the result.

```sh
cd infra

task build          # build local Docker/Podman images
task test CVE=CVE-2021-41773    # true-positive + true-negative for one CVE
task test-all       # all CVEs sequentially
task check-deps     # verify prerequisites
```

Each CVE test covers four cases: `vuln` (HTTP), `vuln_https`, `patched` (HTTP), `patched_https`.

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
4. Add a playbook, register in `site.yml` and `Taskfile.yml`
5. Run `task build && task test CVE=<your-cve>` — expect 4 passing tests

---

## License

MIT — see [LICENSE](LICENSE).
