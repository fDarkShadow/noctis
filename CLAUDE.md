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
│   │   ├── manager.rs      # ScanManager — submit, execute, matched_ports
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

### Context and `{{port}}` variable
`{{port}}` is injected into the context **from the matched service**, before `seed_vars()`.
YAML feeds must not redefine `port:` in their `vars:` section — it would be overwritten anyway.

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
   - Two hosts: `<cve>_vuln` and `<cve>_patched`
   - Required fields: `target_host`, `target_service`, `container_name`, `docker_image`, `expected_result`
   - **No `target_port`** — port is allocated dynamically
3. **Docker images**: `infra/docker/<cve-name>/Dockerfile.vuln` + `Dockerfile.patched`
   - For proprietary appliances (BIG-IP, Exchange, Pulse): minimal Python/Flask mock
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

## Known pitfalls

- **`resp.data` does not exist** — the field is called `resp.banner` on `TcpResult`
- **`port: "{{port}}"` in steps** is an `Option<String>` (not `u16`) — intentional for templates
- **`playbook_dir` in roles** points to `infra/playbooks/`, not `infra/` — always go up two levels (`../../`)
- **Port conflict** — never leave a manual test container running before calling `task test`
- **HTTP Content-Length** — count exact bytes in the body, not characters
- **Local Podman image** — prefix `noctis/` in `docker_image` so the pull is skipped (condition `not docker_image.startswith('noctis/')`)
