# The control plane, built from source in one go.
#
# Both halves are built here rather than uploaded from a laptop: web/pkg/ is
# gitignored, so a deploy that copied it in would ship whatever happened to be on
# the machine that ran `fly deploy`. The image is the build.

FROM rust:1.96-bookworm AS build

# `ring` (via iroh's tls-ring feature) compiles C for wasm32, so the wasm build
# needs a clang with the WebAssembly backend. Debian's has one; Apple's does not,
# which is what scripts/build-wasm.sh goes looking for on a laptop.
RUN apt-get update \
 && apt-get install -y --no-install-recommends clang llvm \
 && rm -rf /var/lib/apt/lists/*

RUN rustup target add wasm32-unknown-unknown
# The installer script, rather than `cargo install wasm-pack`, which builds it
# from source and roughly doubles the length of a cold image build.
RUN curl -sSfL https://rustwasm.github.io/wasm-pack/installer/init.sh | sh

WORKDIR /src
COPY . .

# --release: the bundle is ~4x smaller than the dev build and this is the copy
# every visitor downloads.
RUN ./scripts/build-wasm.sh --release
RUN cargo build --release -p devsite-server

FROM debian:bookworm-slim

# TLS roots, for verifying Shoo's JWKS endpoint.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/target/release/devsite-server /usr/local/bin/devsite-server
COPY --from=build /src/web /app/web

# Defaults for running in a container. Everything that differs per deployment —
# the public origin above all — is set in fly.toml or as a secret.
ENV DEVSITE_BIND=0.0.0.0:8080 \
    DEVSITE_WEB_ROOT=/app/web \
    DEVSITE_DB=/data/devsite.db \
    DEVSITE_STATE_DIR=/data/state

EXPOSE 8080
CMD ["devsite-server"]
