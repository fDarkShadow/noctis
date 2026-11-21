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

The image **bundles the full detection feed set** at `/feeds` (the repository's `tests/` tree),
and its default command is `serve` on `0.0.0.0:8080`:

```sh
docker run --rm -p 8080:8080 ghcr.io/fdarkshadow/noctis:latest
```

Point scans at the bundled feeds with `"tests": ["/feeds/vulnerabilities/"]` — or the relative
`"vulnerabilities/"`, since the working directory is `/feeds`.

### Use your own feeds

Mount a directory over `/feeds` to replace the bundled set, or under it to add to it:

```sh
# Replace the bundled feeds
docker run --rm -p 8080:8080 -v ./my-feeds:/feeds ghcr.io/fdarkshadow/noctis:latest

# Keep the bundled feeds and add your own next to them
docker run --rm -p 8080:8080 -v ./extra-feeds:/feeds/custom ghcr.io/fdarkshadow/noctis:latest
```

`includes:` are resolved relative to each feed file, so keep a feed and the files it includes
together. The bundled feeds are a snapshot taken when the image was built: `:edge` follows
`main`, and a release tag carries the feed set of that release.

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
