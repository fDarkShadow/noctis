# noctis — CLAUDE.md

Working instructions for Claude Code on this project.

> **Autonomous agents** — read this file in full before writing a single line of code.
> It documents every convention, pitfall, and pattern you need. Existing feeds and mocks
> in `tests/vulnerabilities/` and `infra/docker/` are your primary reference — copy and adapt them
> rather than inventing new patterns.

## Architecture

```
noctis/
├── src/                    # Rust engine
│   ├── main.rs             # Entrypoint — subcommand: serve
│   ├── cli.rs              # Clap — ServeArgs
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
│   │   ├── finding.rs      # Finding, Vulnerability, Evidence
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
│   ├── vulnerabilities/    # <product>/<id>.yaml — one file per vulnerability, 0..N CVEs each
│   │   └── .feed-shas.json # sha256 lockfile — see scripts/check_feeds.py
│   └── common/             # Reusable includes
├── scripts/
│   ├── gen_mocks_manifest.py # generates infra/docker/MOCKS.md (mock → consumer feeds)
│   └── check_feeds.py        # sha lockfile + uid-uniqueness check — task feeds-check
└── infra/                  # Reproducible test infrastructure
    ├── Taskfile.yml         # task test ID=CVE-XXXX / task test-all / task mocks-manifest
    ├── playbooks/           # 00-build / 01-start-servers / 10-<product>-<id> / 99-stop-servers
    ├── bake/                # docker-bake HCL files, one per product family
    ├── roles/common_docker/ # Generic role: find port → REST POST /scans → assert → teardown
    ├── inventories/         # <product>/<id>/hosts.yml — one directory per vulnerability
    └── docker/              # Vuln/patched Dockerfiles per product; MOCKS.md (generated)
```

## Essential commands

```sh
cargo build                           # debug build
cargo test                            # unit tests
cargo clippy -- -D warnings           # lint

# REST daemon
noctis serve --host 0.0.0.0 --port 8080

# End-to-end tests (from infra/)
task test ID=CVE-2021-41773           # TP + TN for one vulnerability
task test-all                          # all vulnerabilities
task build                             # build local mock images (podman build)
task mocks-manifest                    # regenerate infra/docker/MOCKS.md
task feeds-check                       # sha lockfile + uid-uniqueness check
task feeds-check -- --write            # regenerate the lockfile after an intentional feed edit
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
cves: []                       # zero, one, or many CVE IDs — see examples below
services: [http, https]        # ports targeted by nmap service name
confidence_base: 0.30          # confidence before steps run
```

`cves` cardinality — a feed is a **vulnerability test**, not a "CVE test":
```yaml
cves: []                                       # misconfiguration / heuristic check, no CVE
cves: [CVE-2021-44228]                         # the common case — exactly one CVE
cves: [CVE-2023-46805, CVE-2024-21887]         # a chain tracked by multiple CVE IDs
```
`category` (optional, free string) still classifies a feed regardless of `cves` —
e.g. `category: exposure` on a 0-CVE check, or `category: auth-bypass` alongside a CVE.

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
cves: [CVE-XXXX-XXXXX]  # [] if no CVE applies, or several for a chain
cvss: 9.8               # omit if cves is empty
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

### `http_request` — result fields
The result stored via `store_as` is an `HttpResult`:
```
resp.status      integer         ← HTTP status code (200, 404, …)
resp.body        string          ← response body as UTF-8
resp.headers     map             ← response headers, keys lowercased
                                   e.g. resp.headers["x-powered-by"]
resp.duration_ms u64
```

Access headers in conditions: `resp_headers["content-type"]` (Rhai flattens
the stored result into prefixed vars: `resp_status`, `resp_body`, `resp_headers`).

### `ssh_check` — result fields
```
resp.banner          string | null   ← SSH version string (e.g. "SSH-2.0-OpenSSH_9.5")
resp.auth_methods    [string]        ← ["publickey", "password", …]
resp.connected       bool
```

## Test infrastructure (infra/)

### Adding a new vulnerability

`<id>` below = the CVE ID when the vulnerability maps to exactly one CVE (the common case),
or a descriptive kebab-case slug when it maps to zero CVEs (misconfiguration/heuristic check)
or to a chain tracked by several CVE IDs (e.g. `ivanti-connect-secure-auth-bypass-rce`).

`<product>` = the mock's product slug — normally the `infra/docker/<product>-mock/`
directory name with the `-mock` suffix (and any trailing CVE-number suffix) stripped, e.g.
`bigip-22986-mock` → `bigip`. Feeds with no dedicated mock (misconfiguration checks) use
`<product>` = `general`. **Before picking a `<product>`, check `infra/docker/MOCKS.md`** —
if a mock for this product already exists, decide deliberately whether to reuse it
(extend, never overwrite existing endpoints — see the shared-mock warning below) or give
your CVE its own dedicated mock directory instead.

1. **Feed**: `tests/vulnerabilities/<product>/<id>.yaml` with a stable UUID v4 uid and
   `cves: []` set to the matching 0, 1, or N CVE IDs. After adding or editing it, run
   `task feeds-check -- --write` and commit the updated `.feed-shas.json` lockfile —
   CI fails otherwise.
2. **Inventory**: `infra/inventories/<product>/<id>/hosts.yml`
   - Four hosts minimum: `<id>_vuln`, `<id>_vuln_https`, `<id>_patched`, `<id>_patched_https`
   - Required fields: `target_host`, `target_service`, `container_name`, `docker_image`, `expected_result`
   - HTTPS hosts: add `container_port: 443` and `target_service: https`
   - **No `target_port`** — port is allocated dynamically
   - On every vuln host set `expected_qod` (highest QoD branch the mock exercises) and
     `expected_min_confidence` (`confidence_base + highest_delta - 0.05`). These are asserted
     by the role to prove the right detection branch fired.
3. **OOB**: if the feed uses `wait_oob`, the OOB steps are guarded by `condition: "oob_enabled"`
   and do **not** fire on the standard 4 hosts (OOB disabled by default). Add two extra hosts
   to exercise the OOB path:
   ```yaml
   <product>_vuln_oob:
     ...same image as vuln...
     noctis_use_oob: true
     expected_result: vulnerable
     expected_qod: 97
     expected_min_confidence: 0.90

   <product>_patched_oob:
     ...same image as patched...
     noctis_use_oob: true
     expected_result: clean   # patched mock must NOT call back
   ```
   The role routes OOB hosts to server B (port 8081) and injects `oob.host` / `oob.port`
   automatically. Also correct the standard 4 hosts' `expected_qod` to the non-OOB max QoD
   (e.g., 75 for response analysis) since OOB steps won't fire there.
4. **Docker images**: `infra/docker/<product-name>/Dockerfile.vuln` + `Dockerfile.patched`
   - All mocks serve HTTP:80 **and** HTTPS:443 (self-signed cert generated at build time via openssl)
   - Python mocks: use `_make_https_server()` + `threading.Thread` pattern (see `bigip-mock/server.py`)
   - Apache/php images: `a2enmod ssl` or `LoadModule ssl_module` + `SSLSessionCache none` + `Mutex file:` (shmcb fails in rootless Podman)
   - EOL base images (e.g. httpd:2.4.49 on Debian Buster): patch apt sources to `archive.debian.org` before installing openssl
   - **If reusing an existing mock directory** (per `infra/docker/MOCKS.md`): only *add*
     new `elif`-branches for your endpoint. Never change an existing endpoint's status
     code, body format, or the exact fields another feed's `match`/`pattern:` depends on
     — this has broken two already-merged CVEs before. Run `task mocks-manifest` after,
     then `task test ID=<other-id>` for every other consumer listed for that mock.
5. **Playbook**: `infra/playbooks/10-<product>-<id>.yml` (copy an existing one — prefix
   `10-` is mandatory; `task test-all` discovers playbooks from `infra/inventories/*/*/`
   directories, not by filename glob). Set `expected_cves: []` (matching the feed's
   `cves:`) alongside the display `cve_id`/`feed_path` vars.
6. **Bake target**: add a matrix target in `infra/bake/<family>.hcl` — see template below

### Python mock template (copy from `infra/docker/bigip-mock/server.py`)

All Python mocks follow this exact structure — copy it, do not invent a new one:

```python
#!/usr/bin/env python3
import os, ssl, threading
from http.server import BaseHTTPRequestHandler, HTTPServer

VULN_MODE = os.environ.get("MYPRODUCT_MODE", "patched") == "vuln"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass

    def _send(self, code, body, ct="text/plain"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if VULN_MODE and self.path == "/vulnerable-endpoint":
            self._send(200, "NOCTIS_MYPRODUCT_CONFIRMED")
        else:
            self._send(404, "Not found")

    def do_POST(self): self.do_GET()

def _make_https_server(port):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain("/certs/server.crt", "/certs/server.key")
    srv = HTTPServer(("0.0.0.0", port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    return srv

if __name__ == "__main__":
    https = _make_https_server(443)
    threading.Thread(target=https.serve_forever, daemon=True).start()
    HTTPServer(("0.0.0.0", 80), Handler).serve_forever()
```

Dockerfile.vuln (same pattern for all Python mocks):
```dockerfile
FROM python:3.11-slim
RUN apt-get update -qq && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir /certs \
    && openssl req -x509 -newkey rsa:2048 -keyout /certs/server.key \
       -out /certs/server.crt -days 3650 -nodes \
       -subj "/CN=noctis-mock"
COPY server.py /app/server.py
ENV MYPRODUCT_MODE=vuln
EXPOSE 80 443
CMD ["python3", "/app/server.py"]
```

Dockerfile.patched: identical but `ENV MYPRODUCT_MODE=patched`.

### Adding a new mock image

Create `infra/docker/<product-name>/Dockerfile.vuln` and `Dockerfile.patched`.
`task build` auto-discovers every directory under `infra/docker/` that contains a
`Dockerfile.vuln` and builds both variants with `podman build`:

```
noctis/<dirname>:vuln     ← from Dockerfile.vuln
noctis/<dirname>:patched  ← from Dockerfile.patched
```

No registration needed — the directory name is the image name.

### Reference feeds to copy from

| Pattern | Best example |
|---------|-------------|
| HTTP path traversal (tcp_connect) | `tests/vulnerabilities/pulse-secure/CVE-2019-11510.yaml` |
| HTTP header injection | `tests/vulnerabilities/shellshock/CVE-2014-6271.yaml` |
| HTTP auth bypass (http_request) | `tests/vulnerabilities/bigip/CVE-2022-1388.yaml` |
| SSH banner version check | `tests/vulnerabilities/regresshion/CVE-2024-6387.yaml` |
| Version via endpoint + OOB | `tests/vulnerabilities/log4shell/CVE-2021-44228.yaml` |
| OGNL/template injection | `tests/vulnerabilities/confluence/CVE-2022-26134.yaml` |
| Multi-step, first half of a 2-CVE chain (`cves: [CVE-2023-46805]`) | `tests/vulnerabilities/ivanti/CVE-2023-46805.yaml` |
| 0-CVE check, loop over a static list (`cves: []`, `category:`) | `tests/vulnerabilities/general/exposed-paths.yaml` |
| 0-CVE check, ssh_check + match | `tests/vulnerabilities/general/ssh-weak-auth.yaml` |
| 0-CVE check, tls_check | `tests/vulnerabilities/general/tls-weak-config.yaml` |

### Dynamic port allocation
The `common_docker` role finds a free port via Python before each test:
```python
import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()
```
Never hardcode `target_port` in an inventory.

### Variable paths in the role
- `playbook_dir` = `infra/playbooks/` (not `infra/`)
- `noctis_feeds_dir` = `/feeds` — the container-internal mount point (host `tests/` is mounted at `/feeds` by `01-start-servers.yml`)

## Feed authoring tooling

`schemas/feed.schema.json` — JSON Schema draft-07 for YAML feeds. Provides validation and autocomplete via the Red Hat YAML extension for `tests/vulnerabilities/*.yaml`.

CLI validation:
```sh
npx ajv-cli validate -s schemas/feed.schema.json -d "tests/vulnerabilities/*/*.yaml" --spec=draft7 --allow-union-types
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
- **`http_request` without `port:`** — if `port:` is omitted the engine defaults to 80/443, ignoring the dynamically allocated test port. Always set `port: "{{port}}"` on every `http_request` step. Without it the request hits port 80/443 (which isn't listening in tests), the HTTP call silently fails, `store_as` is never set, and downstream match steps see the raw `{{resp.body}}` template string — producing 0 findings with no error.
- **`evidence:` in `on_match.finding`** must be a string template, not a YAML list. The engine field is `Option<String>`. A YAML sequence causes serde deserialization to fail silently, dropping the finding. Use: `evidence: "label: {{resp.body}}"`. The correct QoD field name is `qod:` (not `quality_of_detection:`).
- **Debian Bullseye EOL** (httpd:2.4.51, python images using bullseye) — `bullseye-security` does not exist at `archive.debian.org`. Drop the security repo entirely: replace `/etc/apt/sources.list` with `echo "deb http://archive.debian.org/debian bullseye main" > /etc/apt/sources.list`.
- **`action: set_var` uses `var_name:` / `var_value:` fields, NOT a `vars:` map** — using `vars:` silently drops the step (unknown field ignored by serde), `var_name` is None, `run_set_var` returns `MissingField`, the scan runner swallows the error as `vec![]` findings. Always write `var_name: foo` / `var_value: false` on separate lines.
- **`&&` in Rhai conditions works and short-circuits** — `cond_a == true && resp.status == 200` is safe even if `resp` is undefined: if `cond_a` is false, `resp.status` is never evaluated.
- **`cves: []` empty is valid and normal** — don't invent a placeholder CVE ID for a misconfiguration/heuristic check. `category:` is the classifier for 0-CVE feeds, not `cves`.
- **`ScanFilters.exclude_cve` matches on overlap, not equality** — a test is excluded if *any* entry in its `cves:` list appears in the exclusion list, so excluding one CVE of a multi-CVE chain feed excludes the whole feed.
- **Shared mocks silently break other CVEs** — `infra/docker/<product>-mock/` is sometimes reused by more than one CVE (check `infra/docker/MOCKS.md`). Overwriting an existing endpoint/response format instead of adding a new branch breaks the *other* CVE's test without any error appearing in your own — it only surfaces if that CVE happens to be re-run (e.g. in `task test-all`). Always add, never replace; re-test every other consumer listed in `MOCKS.md`.
- **`task feeds-check` fails on a feed you edited** — that's by design: any content change to a file already in `tests/vulnerabilities/.feed-shas.json` must be accompanied by `task feeds-check -- --write` in the same commit, so an unreviewed/accidental edit to an existing feed shows up in the diff instead of silently merging.
