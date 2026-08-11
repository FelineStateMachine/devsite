# Deploying dev.site

The control plane runs as an ordinary process; Cloudflare Tunnel publishes it at
`https://dev.site` with a real certificate and **no inbound port** — the same property the
product itself is built on.

## One-time setup

Both of these open a browser and need you at the keyboard.

```bash
# 1. Authorize cloudflared against the Cloudflare account holding the dev.site zone.
cloudflared tunnel login

# 2. Create the tunnel and point the hostname at it.
./deploy/setup-tunnel.sh
```

`setup-tunnel.sh` creates a tunnel named `devsite`, writes `deploy/cloudflared.yml`, and
adds the DNS records for `dev.site` and `www.dev.site`.

## Running

```bash
./deploy/run.sh
```

That starts the control plane on `127.0.0.1:4000` and the tunnel in front of it.

## The origin is the one irreversible choice

`DEVSITE_PUBLIC_ORIGIN=https://dev.site` is baked into account identity: Shoo derives both
`client_id` and each user's pairwise subject from it. Changing it later does not migrate
accounts — it orphans them. It is set in `deploy/env` and should not change once anyone has
signed in.

## What Cloudflare does and does not see

Cloudflare terminates TLS for the control plane, so it sees profile metadata and API calls.
It never sees private service traffic: the browser's Iroh connection goes to an n0 relay
directly, and that traffic is end-to-end encrypted between the browser and the daemon.

## Caching

`scripts/build-wasm.sh` publishes the wasm bundle under a content hash
(`/pkg/<hash>/…`), so it is served `immutable` and cached at the edge indefinitely. The
manifest naming the current hash, the HTML, and every `/api/` response are `no-cache` or
`no-store`. Redeploying therefore invalidates nothing and never serves a stale bundle.

## Moving off the tunnel later

Nothing above is load-bearing except the hostname. To move to fly.io or a VPS, run the same
binary there with the same `DEVSITE_PUBLIC_ORIGIN`, copy `devsite.db` and
`.devsite-state/capability_signing.key`, and repoint DNS.

**Copy the signing key, do not regenerate it.** Every daemon pinned its public half at
`devsite login`; a new key makes every existing daemon reject every capability.
