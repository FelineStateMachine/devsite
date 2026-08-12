# Keep the checked-in web source readable and only minify the production copy.
FROM node:24-bookworm-slim AS web

WORKDIR /src
COPY web ./web

# Versions are exact so rebuilding a commit cannot silently change its assets.
RUN npm install --global esbuild@0.25.12 html-minifier-terser@7.2.0 \
 && mkdir /out \
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

# The control plane, built from source in one go.
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
COPY --from=web /out /app/web

# Defaults for running in a container. Everything that differs per deployment —
# the public origin above all — is set in fly.toml or as a secret.
ENV DEVSITE_BIND=0.0.0.0:8080 \
    DEVSITE_WEB_ROOT=/app/web \
    DEVSITE_DB=/data/devsite.db \
    DEVSITE_STATE_DIR=/data/state

EXPOSE 8080
CMD ["devsite-server"]
