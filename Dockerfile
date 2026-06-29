# ── Stage 1: dependency plan (cargo-chef) ────────────────────────────────────
FROM docker.io/library/rust:1.96-alpine AS chef
RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static zlib-dev zlib-static libssh2-dev libssh2-static pkgconfig ca-certificates \
    && cargo install cargo-chef --locked
WORKDIR /build

FROM chef AS planner
# Copy only manifests — source changes must NOT invalidate the dep-cook layer
COPY Cargo.toml Cargo.lock ./
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 2: build — fully static (musl + OPENSSL_STATIC) ────────────────────
FROM chef AS builder

# Create the runtime user so we can copy /etc/passwd to the scratch image
RUN adduser -D -u 1000 -s /sbin/nologin noctis

COPY --from=planner /build/recipe.json recipe.json
RUN PKG_CONFIG_ALL_STATIC=1 OPENSSL_STATIC=1 \
    cargo chef cook --release --locked --recipe-path recipe.json

COPY . .
RUN PKG_CONFIG_ALL_STATIC=1 OPENSSL_STATIC=1 \
    cargo build --release --locked

# ── Stage 3: runtime — scratch, zero runtime deps, no shell ──────────────────
FROM scratch

COPY --from=builder /etc/passwd             /etc/passwd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /build/target/release/noctis /usr/local/bin/noctis

USER noctis
EXPOSE 8080

# Feeds are mounted at runtime: docker run -v ./tests:/feeds noctis serve ...
ENTRYPOINT ["/usr/local/bin/noctis"]
CMD ["serve"]
