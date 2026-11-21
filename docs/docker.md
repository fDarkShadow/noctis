---
title: Docker
nav_order: 5
---
{% raw %}
# Docker

## Images

Prebuilt images are published to the **GitHub Container Registry (GHCR)** as a minimal `scratch`
image — a static musl binary, no shell, a few MB — for **`linux/amd64`** and **`linux/arm64`**.

```sh
docker pull ghcr.io/fdarkshadow/noctis:latest
```

## Tags

| Tag | Points to |
|-----|-----------|
| `latest` | the most recent release |
| `X.Y.Z` / `X.Y` | a specific released version |
| `edge` | the latest commit on `main` |

Publishing is automatic: `:edge` on every push to `main`, and the versioned `:X.Y.Z` / `:latest`
tags when a `vX.Y.Z` release is tagged. Browse all tags on the
[package page](https://github.com/fDarkShadow/noctis/pkgs/container/noctis).

## Run

Feeds are read at runtime, so mount them at `/feeds`:

```sh
docker run --rm -v ./tests:/feeds -p 8080:8080 \
  ghcr.io/fdarkshadow/noctis:latest serve --host 0.0.0.0 --port 8080
```

The image `ENTRYPOINT` is the `noctis` binary, so append any CLI arguments directly:

```sh
docker run --rm ghcr.io/fdarkshadow/noctis:latest --help
```

## Build it yourself

```sh
docker build -t noctis .
```

The `Dockerfile` is a multi-stage build (cargo-chef dependency caching → static musl build →
`scratch` runtime), producing a tiny image with no OS and no shell.

{: .note }
> Release images are built in parallel on native `amd64` and `arm64` runners (no emulation),
> then merged into a single multi-arch manifest. A release only proceeds if the tag matches
> the version in `Cargo.toml`.
{% endraw %}
