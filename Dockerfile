# syntax=docker/dockerfile:1
#
# Multi-stage build for Sanctum (personal secrets vault).
#   - builder: rust:1.96-slim (Debian trixie).
#   - runtime: debian:trixie-slim (matching glibc), non-root, ca-certificates.
#
# Sanctum links NO OpenSSL: sqlx uses `rustls` (ring) and the crypto is pure-Rust RustCrypto
# (aes-gcm/sha2), so the binary depends only on glibc — no libssl. `ca-certificates` is kept for
# completeness (sqlx may TLS to a managed Postgres). The audit emitter talks PLAINTEXT HTTP to the
# in-network Watchtower over a raw TCP socket, so no HTTP client crate is needed. The container
# HEALTHCHECK uses the built-in `sanctum healthcheck` subcommand, so no curl is needed either.

FROM rust:1.96-slim AS builder
WORKDIR /build

# Cache the dependency graph first: build a throwaway lib/bin against the real manifest so
# `cargo build` only recompiles our crate when src/ changes, not the whole tree.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN mkdir -p src \
    && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --bin sanctum \
    && rm -rf src

# Now build the real binary. static/ + templates/ are include_str!'d into the binary, so they
# must be present at compile time.
COPY src ./src
COPY static ./static
COPY templates ./templates
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --bin sanctum \
    && strip target/release/sanctum

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Non-root runtime user (no shell, no home writes needed).
RUN useradd --system --uid 10001 --user-group --no-create-home sanctum
COPY --from=builder /build/target/release/sanctum /usr/local/bin/sanctum

USER sanctum
# Default in-container bind; overridable at runtime.
ENV BIND_ADDR=0.0.0.0:8990
EXPOSE 8990

# Dependency-free liveness probe -> GET /healthz on the loopback, exit 0/1.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
    CMD ["sanctum", "healthcheck"]

ENTRYPOINT ["sanctum"]
