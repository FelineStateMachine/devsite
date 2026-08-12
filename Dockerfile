# syntax=docker/dockerfile:1.7

# Keep the checked-in web source readable and only minify the production copy.
FROM node:24-bookworm-slim AS web

WORKDIR /src

# Versions are exact so rebuilding a commit cannot silently change its assets.
RUN npm install --global esbuild@0.25.12 html-minifier-terser@7.2.0

# Tool installation is independent of the source, so ordinary web edits only
# invalidate the small minification layer below.
COPY web ./web
RUN mkdir /out \
 && cp -R web/. /out/ \
 && esbuild web/app.js \
      --format=esm \
      --legal-comments=none \
      --minify \
      --outfile=/out/app.js \
      --target=es2022 \
 && esbuild web/site.css \
      --legal-comments=none \
      --minify \
      --outfile=/out/site.css \
 && html-minifier-terser web/index.html \
      --collapse-whitespace \
      --remove-comments \
      --remove-redundant-attributes \
      --remove-script-type-attributes \
      --remove-style-link-type-attributes \
      --use-short-doctype \
      --output /out/index.html

# The control plane. Web and documentation edits never enter this stage, while
# registry and target caches keep Rust changes incremental across remote builds.
FROM rust:1.96-bookworm AS build

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

RUN --mount=type=cache,id=devsite-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=devsite-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,id=devsite-cargo-target,target=/src/target,sharing=locked \
    cargo build --release --locked -p devsite-server \
 && install -Dm755 target/release/devsite-server /out/devsite-server

FROM debian:bookworm-slim

# TLS roots, for OIDC code exchange and JWKS verification.
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /out/devsite-server /usr/local/bin/devsite-server
COPY --from=web /out /app/web

# Defaults for running in a container. Everything that differs per deployment —
# the public origin above all — is set in fly.toml or as a secret.
ENV DEVSITE_BIND=0.0.0.0:8080 \
    DEVSITE_WEB_ROOT=/app/web \
    DEVSITE_DB=/data/devsite.db \
    DEVSITE_STATE_DIR=/data/state

EXPOSE 8080
CMD ["devsite-server"]
