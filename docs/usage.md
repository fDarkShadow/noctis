---
title: Usage & REST API
nav_order: 3
---
{% raw %}
# Usage & REST API

## CLI

```sh
noctis serve --host 0.0.0.0 --port 8080     # start the REST daemon

noctis -v  serve ...    # INFO logging
noctis -vv serve ...    # DEBUG logging
```

### Out-of-band (blind) detections

Some detections (Log4Shell, SSRF, XXE) confirm a vulnerability through a callback to a server
you control. Enable the built-in OOB server:

```sh
noctis serve --oob --oob-host <public-ip> --oob-port 9090
```

Feeds then use `wait_oob` and the `{{oob_url}}` / `{{oob_token}}` variables. When OOB is not
configured, OOB steps are skipped.

## REST API

| Method | Route | Description |
|--------|-------|-------------|
| `GET` | `/health` | Health check |
| `POST` | `/scans` | Submit a scan |
| `GET` | `/scans` | List scans |
| `GET` | `/scans/{id}` | Scan status |
| `DELETE` | `/scans/{id}` | Cancel a scan |
| `GET` | `/scans/{id}/findings` | Findings for a scan |

### POST /scans

```json
{
  "host": "10.0.0.1",
  "services": [
    { "port": 80,  "service": "http",  "protocol": "tcp" },
    { "port": 443, "service": "https", "protocol": "tcp" }
  ],
  "tests": ["tests/vulnerabilities/"],
  "concurrency": 10
}
```

| Field | Description |
|-------|-------------|
| `host` | Target IP or hostname (required) |
| `services` | Discovered services — `port`, `service` (nmap name), `protocol` (default `tcp`). At least one required |
| `tests` | One or more feed files or directories to run |
| `concurrency` | Parallel tasks, 1–100 (default 5) |
| `webhook_url` | *(optional)* URL notified when the scan completes |
| `filters` | *(optional)* exclude by `exclude_uids`, `exclude_cve`, `exclude_categories`, `exclude_tags` |
| `oob` | *(optional)* `enabled`, `host`, `port` — per-scan OOB callback server |
| `credentials` | *(optional)* `username`, `password`, `token` for authenticated feeds — see below |

### Authenticated scans

```json
"credentials": { "username": "admin", "password": "s3cr3t" }
```

All three fields are optional, but at least one of `username` / `token` must be set and a
`password` needs a `username`; an empty value is rejected with `422`. Feeds read them as
`{{cred_username}}`, `{{cred_password}}`, `{{cred_token}}` and test `{{cred_enabled}}`. A feed
marked `requires_credentials: true` is skipped when no credentials are sent.

{: .note }
> Credentials are write-only. They never appear in `GET /scans`, webhook payloads, logs or
> `Debug` output, and password / token values are replaced by `<redacted>` in findings.

### Findings

Each finding carries the CVE id(s) (possibly empty for a misconfiguration), a severity, a
confidence in `[0,1]`, a [QoD score](writing-feeds.html#confidence--qod), and evidence.

{: .note }
> Confidence is `confidence_base + confidence_delta`, clamped to `[0, 1]`. The QoD reflects *how*
> the detection was proven — see [Writing feeds](writing-feeds.html).
{% endraw %}
