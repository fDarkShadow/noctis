# noctis

Rust vulnerability scanner driven by YAML feeds. A lightweight OpenVAS alternative with reproducible tests, Podman isolation, and a REST API.

## Key concepts

- **Autonomous YAML feeds** — one file per CVE or misconfig, no shared cache
- **Service-based scanning** — feeds declare which services they target (`http`, `https`, `ssh`…), the engine maps them to ports discovered by nmap
- **Graduated confidence** — each finding has a 0–1 confidence score built step by step (OpenVAS QoD compatible)
- **Raw TCP** — `tcp_connect` sends bytes verbatim for encoded payloads (path traversal, injections), bypassing HTTP normalisation
- **Integrated OOB** — HTTP callback server for blind detections (Log4Shell, SSRF, XXE)
- **Protocols** — HTTP/HTTPS, raw TCP, TLS, SSH
- **Reproducible tests** — Ansible + rootless Podman, dynamic port allocation, automated TP/TN assertions

## Requirements

- Rust ≥ 1.75
- Ansible-core ≥ 2.15 (e2e tests only)
- Podman ≥ 4.0 (e2e tests only)
- [Task](https://taskfile.dev) (e2e tests only)

## Installation

```sh
git clone <repo>
cd noctis
cargo build --release
# binary: target/release/noctis
```

## Usage

### CLI mode (one-shot scan)

```sh
noctis scan \
  --host <target> \
  --service http:80 \
  --service https:443 \
  --tests tests/cve/

# Single service, single feed
noctis scan --host 10.0.0.1 --service ssh:22 --tests tests/cve/CVE-2023-48795.yaml

# Verbosity
noctis -v scan ...    # INFO
noctis -vv scan ...   # DEBUG
```

Output is JSON on stdout:

```json
{
  "id": "550e8400-...",
  "status": "completed",
  "target": "10.0.0.1",
  "findings": [
    {
      "test_id": "a3c7f4e2-...",
      "cve": "CVE-2021-41773",
      "severity": "critical",
      "confidence": 0.95,
      "qod": 75,
      "evidence": "LFI confirmed — /etc/passwd via path traversal"
    }
  ],
  "error": null
}
```

Exit code `1` on execution error, `0` otherwise (even with findings).

### Daemon mode (REST API)

```sh
noctis serve --host 0.0.0.0 --port 8080

# With OOB server for blind detections
noctis serve --oob --oob-host <public-ip> --oob-port 9090
```

**Endpoints:**

| Method | Route | Description |
|--------|-------|-------------|
| `GET` | `/health` | Healthcheck |
| `POST` | `/scans` | Start a scan |
| `GET` | `/scans` | List scans |
| `GET` | `/scans/{id}` | Scan state |
| `DELETE` | `/scans/{id}` | Cancel a scan |
| `GET` | `/scans/{id}/findings` | Findings for a scan |

**POST /scans example:**

```json
{
  "host": "10.0.0.1",
  "services": [
    { "port": 80,  "service": "http",  "protocol": "tcp" },
    { "port": 443, "service": "https", "protocol": "tcp" }
  ],
  "tests": ["tests/cve/", "tests/misconfig/"],
  "concurrency": 5
}
```

## YAML feed format

### Full structure

```yaml
uid: a3c7f4e2-1b9d-4f6a-8e3c-2d5a0f1e9b4c   # stable UUID v4 — never change
name: "Apache httpd 2.4.49 Path Traversal / RCE (CVE-2021-41773)"
type: cve                   # cve | misconfig
cve: CVE-2021-41773
cvss: 9.8
severity: critical          # info | low | medium | high | critical
confidence_base: 0.30       # floor before any step runs
tags: [apache, path-traversal, rce]
services: [http, https]     # nmap service names to target (empty = all)
author: noctis
version: "1.0.0"
references:
  - "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"

steps:
  - id: probe
    action: tcp_connect
    port: "{{port}}"
    send: "GET /icons/.%2e/.%2e/etc/passwd HTTP/1.0\r\nHost: {{target_host}}\r\n\r\n"
    store_as: resp

  - id: match
    action: match
    source: resp.banner
    pattern: "root:[x*!]:0:0"
    on_match:
      finding:
        confidence_delta: 0.65
        qod: 75
        evidence: "LFI confirmed — /etc/passwd readable"
      stop: true
```

### Service → port matching

The engine computes which ports to run each feed against:

- `services: []` → runs on **all** discovered ports
- `services: [http]` → only ports whose nmap service is `http`
- `services: [https]` → only ports whose nmap service is `https`

`{{port}}` is injected automatically from the matched service. **Never redefine it in `vars:`.**

### Automatic variables

| Variable | Value |
|----------|-------|
| `{{target_host}}` | Target host |
| `{{port}}` | Current service port (injected by the engine) |
| `{{oob_token}}` | Unique UUID for this run |
| `{{oob_url}}` | Full OOB server URL |

### Available actions

| Action | Description |
|--------|-------------|
| `http_request` | HTTP/HTTPS request via reqwest |
| `tcp_connect` | Raw TCP socket + banner grab (no URL normalisation) |
| `tls_check` | TLS inspection — version, cipher, certificate |
| `ssh_check` | SSH banner + authentication methods |
| `match` | Regex pattern match on a context variable |
| `script` | Arbitrary Rhai script |
| `wait_oob` | Wait for an OOB HTTP callback |
| `set_var` | Assign a variable in the context |

### `tcp_connect` vs `http_request`

**Use `tcp_connect` for any payload encoded in the path** (path traversal, `%2e`, `%2f`, etc.).
Reqwest normalises URLs before sending: `%2e` → `.` then resolves `../`, breaking the exploit.
`tcp_connect` sends bytes verbatim.

```yaml
# Correct — payload preserved
- action: tcp_connect
  send: "GET /cgi-bin/.%2e/.%2e/etc/passwd HTTP/1.0\r\nHost: {{target_host}}\r\n\r\n"
  store_as: resp

# Result — use .banner (not .data)
- action: match
  source: resp.banner
  pattern: "root:.*:0:0"
```

### Confidence levels (QoD)

| QoD | Meaning |
|-----|---------|
| 50 | General detection (banner, version) |
| 70 | Specific banner match |
| 75 | Functional proof (LFI /etc/passwd, application response) |
| 97 | OOB callback received, or confirmed RCE |
| 100 | Full exploit with verified output |

### Conditions and Rhai scripting

```yaml
- id: conditional-step
  action: match
  source: resp.banner
  pattern: "Apache"
  condition: "resp_status >= 200 && resp_status < 300"
  on_match:
    condition: "resp_banner.len > 100"
    finding:
      confidence_delta: 0.20
```

### Loops

```yaml
steps:
  - id: probe-paths
    action: http_request
    path: "{{current_path}}"
    loop:
      over: [/admin, /.git/config, /actuator/env]
      var: current_path
    store_as: resp
    on_success:
      condition: "resp_status == 200"
      finding:
        title: "Exposed path: {{current_path}}"
        confidence_delta: 0.10
```

## Available feeds

| Feed | Product | Services | Detection method |
|------|---------|----------|-----------------|
| `CVE-2014-6271.yaml` | GNU Bash (Shellshock) | http, https | `() {:;};` header injection + RCE pattern |
| `CVE-2017-9841.yaml` | PHPUnit | http, https | `eval-stdin.php` + MD5 RCE proof |
| `CVE-2019-11510.yaml` | Pulse Connect Secure | https | `%2F` path traversal + `/etc/passwd` |
| `CVE-2021-26855.yaml` | Exchange ProxyLogon | https | SSRF NTLM via `X-BEResource` |
| `CVE-2021-41773.yaml` | Apache 2.4.49 | http, https | LFI `/icons/` + RCE via mod_cgi |
| `CVE-2021-44228.yaml` | Log4j2 (Log4Shell) | http, https | OOB JNDI — requires `--oob` |
| `CVE-2022-1388.yaml` | F5 BIG-IP | https | iControl REST auth bypass |
| `CVE-2022-26134.yaml` | Confluence | http, https | OGNL injection RCE |
| `CVE-2023-48795.yaml` | SSH (Terrapin) | ssh | ChaCha20-Poly1305 negotiation + banner |

## Test infrastructure (infra/)

Reproducible end-to-end tests: Podman containers (vuln + patched), dynamic port, automatic assertions.

### Commands

```sh
cd infra

# Build local images (proprietary mocks)
task build

# Test a single CVE (TP + TN)
task test CVE=CVE-2021-41773

# Test all CVEs sequentially
task test-all

# Check prerequisites
task check-deps
```

### CVE test structure

Each CVE has:
- `infra/inventories/<CVE>/hosts.yml` — two hosts: `<cve>_vuln` (TP) and `<cve>_patched` (TN)
- `infra/playbooks/<CVE>.yml` — playbook delegating to the `common_docker` role
- `infra/docker/<name>/Dockerfile.vuln` + `Dockerfile.patched` — images

The `common_docker` role:
1. Allocates a free port dynamically (Python socket)
2. Starts the container
3. Waits for the service to respond
4. Runs `noctis scan --service <svc>:<port>`
5. Checks the finding count (assert TP or TN)
6. Tears down the container

### Inventory template

```yaml
# infra/inventories/CVE-XXXX-XXXXX/hosts.yml
all:
  children:
    cve_xxxx:
      hosts:
        app_vuln:
          ansible_host: localhost
          ansible_connection: local
          target_host: "127.0.0.1"
          target_service: http        # nmap service — must match the feed
          container_name: noctis_cve_xxxx_vuln
          docker_image: "noctis/app-cve-xxxx:vuln"
          expected_result: vulnerable # feed MUST produce a finding

        app_patched:
          ansible_host: localhost
          ansible_connection: local
          target_host: "127.0.0.1"
          target_service: http
          container_name: noctis_cve_xxxx_patched
          docker_image: "noctis/app-cve-xxxx:patched"
          expected_result: clean      # feed MUST NOT produce a finding
```

**`target_port` must not appear in the inventory** — it is allocated dynamically at each run.

### Adding a new CVE

1. `tests/cve/CVE-XXXX-XXXXX.yaml` — feed with stable UUID v4 uid and `services:` set
2. `infra/inventories/CVE-XXXX-XXXXX/hosts.yml` — two hosts without `target_port`
3. `infra/docker/<name>/Dockerfile.vuln` + `Dockerfile.patched` (or Flask mock for proprietary appliances)
4. `infra/playbooks/CVE-XXXX-XXXXX.yml` — copy an existing one
5. `infra/site.yml` — add `import_playbook: playbooks/CVE-XXXX-XXXXX.yml`
6. `infra/Taskfile.yml` — add the CVE to `vars.INVENTORIES`
