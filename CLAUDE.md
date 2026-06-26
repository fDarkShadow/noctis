# noctis — CLAUDE.md

Working instructions for Claude Code on this project.

## Architecture

```
noctis/
├── src/                    # Rust engine
│   ├── main.rs             # Entrypoint — subcommands serve / scan
│   ├── cli.rs              # Clap — ScanArgs, ServeArgs
│   ├── api/                # REST API (axum 0.8) — POST/GET /scans
│   ├── scan/               # Scan orchestration
│   │   ├── manager.rs      # ScanManager — submit, execute, matched_services
│   │   ├── request.rs      # ScanRequest, DiscoveredService, ScanFilters
│   │   └── state.rs        # ScanState, ScanStatus, ScanSummary
│   ├── engine/             # YAML test execution engine
│   │   ├── runner.rs       # Runner::run() — iterates steps
│   │   ├── context.rs      # Context — vars, findings, target_host/port
│   │   ├── step.rs         # Dispatch by action
│   │   ├── finding.rs      # handle_outcome(), build_finding()
│   │   └── actions/        # http, connect (tcp/tls/ssh), logic, oob
│   ├── model/              # Structs deserialized from YAML
│   │   ├── test_def.rs     # TestDef — metadata + steps + services
│   │   ├── step.rs         # Step — all fields of a step
│   │   ├── finding.rs      # Finding, FindingKind, Evidence
│   │   └── severity.rs     # Severity enum
│   ├── checks/             # Low-level network primitives
│   │   ├── http.rs         # reqwest wrapper
│   │   ├── tcp.rs          # connect_and_grab() — raw socket
│   │   ├── tls.rs          # rustls — cert/cipher inspection
│   │   └── ssh.rs          # libssh2 — banner + auth methods
│   ├── loader/             # YAML loading + resolution (includes, glob)
│   ├── expr/               # {{var}} templates and Rhai scripts
│   └── oob/                # OOB HTTP server for blind callbacks
├── tests/                  # YAML feeds
│   ├── cve/                # One file per CVE
│   ├── misconfig/          # Misconfiguration checks
│   └── common/             # Reusable includes
└── infra/                  # Reproducible test infrastructure
    ├── Taskfile.yml         # task test CVE=CVE-XXXX / task test-all
    ├── site.yml             # Imports all CVE playbooks
    ├── playbooks/           # One playbook per CVE
    ├── roles/common_docker/ # Generic role: find port → start → scan → assert → teardown
    ├── inventories/         # One directory per CVE (hosts.yml)
    └── docker/              # Vuln/patched Dockerfiles per CVE
```

## Essential commands

```sh
cargo build                           # debug build
cargo test                            # unit tests (79 tests)
cargo clippy -- -D warnings           # lint

# Scan CLI
noctis scan \
  --host 10.0.0.1 \
  --service http:80 --service https:443 \
  --tests tests/cve/CVE-2021-41773.yaml

# REST daemon
noctis serve --host 0.0.0.0 --port 8080

# End-to-end tests (from infra/)
task test CVE=CVE-2021-41773          # TP + TN for one CVE
task test-all                          # all CVEs
task build                             # build local Docker images
```

## Key data model

### ScanRequest
```rust
pub struct ScanRequest {
    pub host: String,
    pub services: Vec<DiscoveredService>,  // required, min 1
    pub tests: Vec<String>,
    pub concurrency: usize,
    // + webhook_url, oob, filters
}

pub struct DiscoveredService {
    pub port: u16,
    pub service: String,   // "http", "https", "ssh", etc.
    pub protocol: String,  // "tcp" (default)
}
```

### TestDef (YAML)
```yaml
uid: <uuid-v4-stable>          # immutable identifier
type: cve | misconfig
services: [http, https]        # ports targeted by nmap service name
confidence_base: 0.30          # confidence before steps run
```

### Service → port matching
- Feed `services: []` → runs on **all** discovered ports
- Feed `services: [http]` → only ports whose `service == "http"`
- No match → feed does not run (no task created)

### Context variables (injected automatically)

| Variable | Value |
|----------|-------|
| `{{target_host}}` | Target IP / hostname |
| `{{port}}` | Port of the matched service |
| `{{scheme}}` | `http` or `https` — derived from the service name |
| `{{oob_token}}` | UUID unique to this test run |
| `{{oob_url}}` | Full OOB callback URL |
| `{{oob_host}}` | OOB server host (only when `--oob` is configured) |
| `{{oob_port}}` | OOB server port |
| `{{oob_enabled}}` | `true` when OOB is active, `false` otherwise |

`{{port}}` and `{{scheme}}` are injected **from the matched service**, before `seed_vars()`.
YAML feeds must not redefine `port:` or `scheme:` in their `vars:` section — they would be overwritten.

### `tcp_connect` and HTTPS
`tcp_connect` auto-detects TLS from `{{scheme}}`: when the matched service is `https`, the raw TCP connection is wrapped in TLS (self-signed certs are accepted via `NoCertVerifier`). No change needed in the YAML — the same step works for both HTTP and HTTPS targets.

## YAML feed conventions

### Required structure
```yaml
uid: <uuid-v4>          # stable, unique, never change
name: "..."
type: cve
cve: CVE-XXXX-XXXXX
cvss: 9.8
severity: critical
confidence_base: 0.30   # low — steps raise it
tags: [...]
services: [http, https] # always set
author: noctis
version: "1.0.0"

steps:
  - id: probe
    action: tcp_connect | http_request | match | ...
```

### Confidence levels (QoD)
| QoD | Meaning |
|-----|---------|
| 50  | General detection (banner/version) |
| 70  | Banner match |
| 75  | Response analysis (LFI /etc/passwd) |
| 97  | OOB callback or confirmed RCE |
| 100 | Full exploit |

`confidence_base + confidence_delta` is clamped to `[0.0, 1.0]`.

### Path traversal → always use `tcp_connect`
**Reqwest normalises URLs**: `%2e` → `.` then resolves `../` before sending.
For any CVE with an encoded payload in the path (`%2e`, `%2f`, etc.),
use `tcp_connect` with `send:` in verbatim HTTP/1.0:

```yaml
- action: tcp_connect
  port: "{{port}}"
  send: "GET /icons/.%2e/.%2e/.%2e/etc/passwd HTTP/1.0\r\nHost: {{target_host}}\r\n\r\n"
  store_as: resp

- action: match
  source: resp.banner    # correct field — not resp.data
  pattern: "root:.*:0:0"
```

### `tcp_connect` — result fields
The result stored via `store_as` is a `TcpResult`:
```
resp.connected   bool
resp.banner      string | null   ← always use .banner, not .data
resp.duration_ms u64
```

## Test infrastructure (infra/)

### Adding a new CVE

1. **Feed**: `tests/cve/CVE-XXXX-XXXXX.yaml` with a stable UUID v4 uid
2. **Inventory**: `infra/inventories/CVE-XXXX-XXXXX/hosts.yml`
   - Four hosts: `<cve>_vuln`, `<cve>_vuln_https`, `<cve>_patched`, `<cve>_patched_https`
   - Required fields: `target_host`, `target_service`, `container_name`, `docker_image`, `expected_result`
   - HTTPS hosts: add `container_port: 443` and `target_service: https`
   - **No `target_port`** — port is allocated dynamically
3. **Docker images**: `infra/docker/<cve-name>/Dockerfile.vuln` + `Dockerfile.patched`
   - All mocks serve HTTP:80 **and** HTTPS:443 (self-signed cert generated at build time via openssl)
   - Python mocks: use `_make_https_server()` + `threading.Thread` pattern (see `bigip-mock/server.py`)
   - Apache/php images: `a2enmod ssl` or `LoadModule ssl_module` + `SSLSessionCache none` + `Mutex file:` (shmcb fails in rootless Podman)
   - EOL base images (e.g. httpd:2.4.49 on Debian Buster): patch apt sources to `archive.debian.org` before installing openssl
4. **Playbook**: `infra/playbooks/CVE-XXXX-XXXXX.yml` (copy an existing one)
5. **site.yml**: add `import_playbook: playbooks/CVE-XXXX-XXXXX.yml`
6. **Taskfile.yml**: add the CVE to `vars.INVENTORIES`

### Dynamic port allocation
The `common_docker` role finds a free port via Python before each test:
```python
import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()
```
Never hardcode `target_port` in an inventory.

### Variable paths in the role
- `playbook_dir` = `infra/playbooks/` (not `infra/`)
- `noctis_bin` = `{{ playbook_dir }}/../../target/debug/noctis`
- `noctis_feeds_dir` = `{{ playbook_dir }}/../../tests`

## Feed authoring tooling

`schemas/feed.schema.json` — JSON Schema draft-07 for YAML feeds. Provides validation and autocomplete via the Red Hat YAML extension (already wired in `.vscode/settings.json` for `tests/cve/*.yaml` and `tests/misconfig/*.yaml`).

CLI validation:
```sh
npx ajv-cli validate -s schemas/feed.schema.json -d "tests/cve/*.yaml" --spec=draft7 --allow-union-types
```

## Known pitfalls

- **`resp.data` does not exist** — the field is called `resp.banner` on `TcpResult`
- **`port: "{{port}}"` in steps** is an `Option<String>` (not `u16`) — intentional for templates
- **`playbook_dir` in roles** points to `infra/playbooks/`, not `infra/` — always go up two levels (`../../`)
- **Port conflict** — never leave a manual test container running before calling `task test`
- **HTTP Content-Length** — count exact bytes in the body, not characters
- **Local Podman image** — prefix `noctis/` in `docker_image` so the pull is skipped (condition `not docker_image.startswith('noctis/')`)
- **`SSLSessionCache shmcb`** — crashes in rootless Podman (`Invalid argument: Couldn't set permissions on ssl-cache mutex`). Use `SSLSessionCache none` + `Mutex file:/path ssl-cache` instead
- **Debian Buster EOL** (httpd:2.4.49) — `apt-get update` fails. Prefix with: `sed -i 's|deb.debian.org|archive.debian.org|g; s|security.debian.org|archive.debian.org|g; /buster-updates/d' /etc/apt/sources.list`
- **`rustls` CryptoProvider** — `ClientConfig::builder().dangerous()` panics unless the provider is set. Always use `ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))`
- **Condition on undefined Rhai var** — accessing an undefined variable in a condition throws, `unwrap_or(false)` silently skips the step. Initialise with `action: set_var` before use
- **`maven_resp_status`** does not exist — use `maven_resp.status` (dot notation into the stored result)
