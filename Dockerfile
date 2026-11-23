# Toolchain and dependency versions are pinned by this base image tag and by
# Cargo.lock only — no third-party build tooling is installed or compiled.

# ── Stage 1: toolchain + static system libraries ─────────────────────────────
FROM docker.io/library/rust:1.96-alpine AS base
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static zlib-dev zlib-static libssh2-dev libssh2-static pkgconfig ca-certificates \
    && adduser -D -u 1000 -s /sbin/nologin noctis
ENV PKG_CONFIG_ALL_STATIC=1 OPENSSL_STATIC=1
WORKDIR /build

# ── Stage 2: version-masked manifests ────────────────────────────────────────
# The dependency layer below is keyed on these files. Masking our own package
# version means a release bump (0.1.0 → 0.2.0) does not invalidate it.
FROM base AS manifests
COPY Cargo.toml Cargo.lock ./
RUN awk '!done && /^version = /{print "version = \"0.0.0\""; done=1; next} {print}' Cargo.toml > t && mv t Cargo.toml \
    && awk 'prev == "name = \"noctis\"" && /^version = /{$0 = "version = \"0.0.0\""} {print; prev = $0}' Cargo.lock > t && mv t Cargo.lock

# ── Stage 3: build — fully static (musl + OPENSSL_STATIC) ────────────────────
FROM base AS builder

# Dependencies only, against an empty main.rs. Cached until a dependency
# changes in Cargo.toml / Cargo.lock, so a source-only change never recompiles
# them.
COPY --from=manifests /build/Cargo.toml /build/Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
    && cargo build --release --locked \
    && rm -rf src

# Real manifests and sources: only the noctis crate itself is compiled.
# `touch` because COPY keeps the files' original mtimes, which can be older than
# the stub build above — cargo would otherwise keep the stub binary.
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN touch src/main.rs && cargo build --release --locked

# ── Stage 4: runtime — scratch, zero runtime deps, no shell ──────────────────
FROM scratch

COPY --from=builder /etc/passwd             /etc/passwd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /build/target/release/noctis /usr/local/bin/noctis

# Detection feeds are bundled at /feeds (same tree as the repo's tests/, so
# `includes:` resolve). Last layer on purpose: a feed-only change rebuilds just
# this layer. To use your own feeds, mount over it:
#   docker run -v ./my-feeds:/feeds ...          (replace the bundled set)
#   docker run -v ./extra:/feeds/custom ...      (add to the bundled set)
COPY tests /feeds
WORKDIR /feeds

USER noctis
EXPOSE 8080

# OCI metadata that holds for any build, local ones included
# (`docker build -t noctis .`). CI (.github/workflows/docker-image.yml) sets the
# same keys plus version/revision/created, and repeats them as index annotations
# for the GHCR package page; on identical keys the CI value wins. Metadata only:
# no layer, and kept last so it never invalidates the build cache above.
LABEL org.opencontainers.image.title="noctis" \
      org.opencontainers.image.description="Black-box vulnerability scanner with a REST API, driven by YAML feeds (bundled at /feeds)." \
      org.opencontainers.image.source="https://github.com/fDarkShadow/noctis" \
      org.opencontainers.image.url="https://github.com/fDarkShadow/noctis" \
      org.opencontainers.image.documentation="https://fdarkshadow.github.io/noctis/" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="fDarkShadow"

# Scan requests can then use "tests": ["/feeds/vulnerabilities/"]
# (or the relative "vulnerabilities/", resolved against WORKDIR).
ENTRYPOINT ["/usr/local/bin/noctis"]
CMD ["serve"]
