---
title: Getting started
nav_order: 2
---

# Getting started
{: .no_toc }

1. TOC
{:toc}

---

## Install

### Docker (recommended)

Prebuilt images are published to the GitHub Container Registry for `linux/amd64` and
`linux/arm64`. See [Docker]({% link docker.md %}) for the full tag scheme.

```sh
docker pull ghcr.io/fdarkshadow/noctis:latest
```

### From source

You need a recent stable Rust toolchain.

```sh
git clone https://github.com/fDarkShadow/noctis
cd noctis
cargo build --release
# binary at ./target/release/noctis
```

On Debian/Ubuntu, the build needs `pkg-config` and OpenSSL headers:

```sh
sudo apt-get install -y pkg-config libssl-dev
```

## Run the daemon

noctis runs as a REST service. Feeds live in `tests/` and are read at scan time.

```sh
# From source
./target/release/noctis serve --host 0.0.0.0 --port 8080

# Docker (mount your feeds at /feeds)
docker run --rm -v ./tests:/feeds -p 8080:8080 \
  ghcr.io/fdarkshadow/noctis:latest serve --host 0.0.0.0 --port 8080
```

## Submit your first scan

Describe the target host and its discovered services, then point at one or more feed paths:

```sh
curl -s -X POST http://localhost:8080/scans \
  -H "Content-Type: application/json" \
  -d '{
    "host": "10.0.0.1",
    "services": [
      {"port": 80,  "service": "http",  "protocol": "tcp"},
      {"port": 443, "service": "https", "protocol": "tcp"}
    ],
    "tests": ["tests/vulnerabilities/"],
    "concurrency": 10
  }' | jq .
```

The response contains a scan `id`. Poll it for findings:

```sh
curl -s http://localhost:8080/scans/<id>/findings | jq .
```

```json
[
  {
    "cve_ids": ["CVE-2021-41773"],
    "severity": "critical",
    "confidence": 0.95,
    "qod": 75,
    "evidence": {
      "response_excerpt": "LFI confirmed — /etc/passwd readable via path traversal"
    }
  }
]
```

{: .note }
> Services are matched against each feed's `services:` field, so only the relevant feeds run on
> each port. A feed with `services: []` runs on every discovered service.

## Next steps

- [Usage & REST API]({% link usage.md %}) — all endpoints and CLI options.
- [Writing feeds]({% link writing-feeds.md %}) — author your own detections.
