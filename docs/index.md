---
title: Home
layout: home
nav_order: 1
description: "noctis — a Rust black-box vulnerability scanner driven by self-contained YAML feeds."
permalink: /
---

# noctis
{: .fs-9 }

A Rust black-box vulnerability scanner driven by self-contained YAML feeds —
evidence-graded CVE and misconfiguration detection for live services.
{: .fs-6 .fw-300 }

[Get started]({% link getting-started.md %}){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[View on GitHub](https://github.com/fDarkShadow/noctis){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## Why noctis?

- **Proof over guessing** — a finding is raised only when a step *observes* the vulnerable
  behaviour (an LFI response, an unauthenticated reply, an out-of-band callback), and each is
  graded with an OpenVAS-style Quality-of-Detection (QoD) score.
- **Detection as data** — every check is a self-contained YAML feed, not compiled code. Read it,
  audit it, or write your own in minutes.
- **No agent, no shared state** — point it at live services over the network; each feed is
  standalone and reproducible.
- **Rust single binary** — fast, memory-safe, with a REST API for automation and CI/CD.

{: .note }
> If you've used **Nuclei** or **OpenVAS**: noctis sits between them — data-driven feeds like
> the former, evidence-graded findings like the latter.

## Explore the docs

- [**Getting started**]({% link getting-started.md %}) — install, run the daemon, submit your first scan.
- [**Usage & REST API**]({% link usage.md %}) — endpoints, request/response, CLI flags, OOB.
- [**Writing feeds**]({% link writing-feeds.md %}) — the YAML format, step actions, variables, QoD.
- [**Docker**]({% link docker.md %}) — container images (GHCR), tags, multi-arch.
- [**Contributing**]({% link contributing.md %}) — how to add a feed or an engine capability.

---

## In one command

```sh
docker run --rm -v ./tests:/feeds -p 8080:8080 \
  ghcr.io/fdarkshadow/noctis:latest serve --host 0.0.0.0 --port 8080
```
