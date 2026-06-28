# ── Stage 1: dependency plan (cargo-chef) ────────────────────────────────────
FROM docker.io/library/rust:1-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /build

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Stage 2: build ────────────────────────────────────────────────────────────
FROM chef AS builder

# pkg-config + libssl-dev needed to compile vendored libssh2 against system OpenSSL
RUN apt update \
    && apt install -y --no-install-recommends pkg-config libssl-dev \
    && apt clean

# Warm up the dependency cache before copying application source
COPY --from=planner /build/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

COPY . .
RUN cargo build --release --locked

# ── Stage 3: runtime ──────────────────────────────────────────────────────────
FROM gcr.io/distroless/cc-debian12:nonroot

# libssh2 is vendored (statically linked into the binary).
# distroless/cc includes libc6 + libgcc-s1 but not OpenSSL or zlib.
COPY --from=builder /lib/x86_64-linux-gnu/libssl.so.3    /lib/x86_64-linux-gnu/libssl.so.3
COPY --from=builder /lib/x86_64-linux-gnu/libcrypto.so.3 /lib/x86_64-linux-gnu/libcrypto.so.3
COPY --from=builder /lib/x86_64-linux-gnu/libz.so.1      /lib/x86_64-linux-gnu/libz.so.1

COPY --from=builder /build/target/release/noctis /usr/local/bin/noctis

# Feeds are served from a mounted volume at runtime:
#   docker run -v ./tests:/feeds noctis serve --host 0.0.0.0 --port 8080
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/noctis"]
CMD ["serve"]
