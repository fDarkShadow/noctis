---
title: noctis — Rust vulnerability scanner driven by YAML feeds
description: >-
  noctis is an open-source, black-box vulnerability scanner written in Rust. It detects
  CVEs and misconfigurations by running structured YAML feeds against live services, with
  evidence-graded (QoD) findings and a REST API for CI/CD.
---

# noctis

**A Rust black-box vulnerability scanner driven by YAML feeds.**

noctis detects CVEs and misconfigurations by running structured, self-contained YAML test
sequences against live services — no agent, no shared cache, no false-positive-prone version
guessing. Every feed is a reproducible detection unit, and every finding is graded with an
OpenVAS-style Quality-of-Detection (QoD) score.

[View the project on GitHub →](https://github.com/fDarkShadow/noctis)

## Why noctis?

- **Proof over guessing** — a finding is raised only when a step *observes* the vulnerable
  behaviour (an LFI response, an unauthenticated reply, an out-of-band callback).
- **Detection as data** — each check is a YAML feed, not compiled code: readable, auditable,
  and quick to author.
- **No agent, no shared state** — point it at live services over the network; each feed stands
  alone and is reproducible.
- **Rust single binary** — fast, memory-safe, with a REST API for automation and CI/CD.

If you've used **Nuclei** or **OpenVAS**: noctis sits between them — data-driven feeds like the
former, evidence-graded findings like the latter.

## Use cases

- **DevSecOps / CI-CD** — submit scans from a pipeline via the REST API and gate releases.
- **Pentest & red team** — fast, evidence-based black-box checks against live targets.
- **Continuous exposure monitoring** — open databases, unauthenticated services, weak TLS.
- **Custom detections** — write an in-house check as a YAML feed without touching the engine.

## Quick start

```sh
git clone https://github.com/fDarkShadow/noctis
cd noctis
cargo build --release
./target/release/noctis serve --host 0.0.0.0 --port 8080
```

Then submit a scan over the REST API — see the
[README](https://github.com/fDarkShadow/noctis#quick-start) for the full example.

### Or run the container (GHCR)

Prebuilt `linux/amd64` + `linux/arm64` images are published to the GitHub Container Registry:

```sh
docker run --rm -v ./tests:/feeds -p 8080:8080 \
  ghcr.io/fdarkshadow/noctis:latest serve --host 0.0.0.0 --port 8080
```

Tags: `latest` and `X.Y.Z` (releases), `edge` (latest `main`).

## Links

- [Source & documentation](https://github.com/fDarkShadow/noctis)
- [Contributing guide](https://github.com/fDarkShadow/noctis/blob/main/CONTRIBUTING.md)
- [Security policy](https://github.com/fDarkShadow/noctis/blob/main/SECURITY.md)
- [Container image (GHCR)](https://github.com/fDarkShadow/noctis/pkgs/container/noctis)

---

*noctis is released under the MIT License.*
