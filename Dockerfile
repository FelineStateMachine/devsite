# The control plane, built from source in one go.
#
FROM rust:1.96-bookworm AS build

WORKDIR /src
COPY . .

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
