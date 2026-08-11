# Deploying dev.site

The control plane runs on [Fly](https://fly.io): one machine, one volume, SQLite on it.
`fly.toml` and `Dockerfile` in the repository root are the whole deployment.

One machine is deliberate. A Fly volume attaches to a single machine in a single region,
and nothing here wants a second writer. Since the heartbeat went away the database is
read-mostly — a few hundred bytes per account, and a handful of writes per user per
lifetime — so this shape has a lot of room in it.

## The two things that cannot be undone

**`DEVSITE_PUBLIC_ORIGIN`.** Shoo derives `client_id` and every user's pairwise subject
from it. Changing it after anyone has signed in does not migrate accounts, it orphans them.
It lives in `fly.toml` and must match the hostname browsers actually load.

**The capability signing key.** Every daemon pinned its public half at `devsite login` and
refuses capabilities signed by anything else. Lose it and every daemon in the world stops
working, with no way to recover but re-running `devsite login` everywhere.

So it is a Fly secret rather than a file on the volume: encrypted at rest, injected into
the machine's environment, and not tied to the survival of one volume on one host. The
server prefers `DEVSITE_SIGNING_KEY` when it is set and falls back to `DEVSITE_STATE_DIR`
when it is not, which is what keeps local development unchanged.

## One-time setup

```bash
fly apps create devsite

# --yes answers the "every volume is pinned to one physical host, make two"
# warning, which cannot prompt without a terminal. One volume is the intended
# shape here: a second would be a second SQLite file on a second machine, both
# taking writes and neither aware of the other. Redundancy needs LiteFS, not
# another volume.
fly volumes create devsite_data --region sjc --size 1 --yes

# 32 random bytes as 64 hex characters. Generate it here, keep a copy somewhere
# you would still have after losing this laptop, and never commit it.
fly secrets set DEVSITE_SIGNING_KEY="$(openssl rand -hex 32)"
```

To carry an existing key over instead of generating one:

```bash
fly secrets set DEVSITE_SIGNING_KEY="$(xxd -p -c 64 data/state/capability_signing.key)"
```

Check it against what daemons pinned before trusting it — `fly logs` prints the public half
at boot, and `devsite status` prints what the daemon expects.

### The hostname

The first deploy provisions a shared v4 and a dedicated v6 by itself, so there is usually
nothing to allocate:

```bash
fly ips list                      # the addresses to point DNS at
```

At Cloudflare, on the `dev.site` zone, add `A` and `AAAA` records for the apex pointing at
those addresses, **DNS only — grey cloud, not proxied**. Fly needs to answer the ACME
challenge on the hostname itself; proxying breaks issuance and puts a second TLS terminator
in front of a site whose whole argument is about who can see what.

```bash
fly certs add dev.site
fly certs show dev.site           # until it reports Ready
```

## Deploying

```bash
fly deploy
```

Fly builds the image remotely — there is no need for a local Docker daemon. The build runs
`scripts/build-wasm.sh --release` and `cargo build --release -p devsite-server` inside the
image, so `web/pkg/` is never uploaded from a laptop and the bundle always matches the
source that produced the binary.

A deploy replaces the machine, which means a few seconds where the site is down. That is
the cost of one volume, and it is the right trade at this size.

## Backups

Fly snapshots volumes daily, five days' retention. That covers the machine dying; it does
not cover "I want the database on my laptop", which is worth having:

```bash
fly ssh console -C "sqlite3 /data/devsite.db '.backup /data/backup.db'"
fly sftp get /data/backup.db ./devsite-backup.db
```

The signing key is not on the volume and is not in these backups. Keep it separately — it
is the part that cannot be regenerated.

## Configuration

Set in `fly.toml`, except the secret.

| Variable | Where | Notes |
| --- | --- | --- |
| `DEVSITE_PUBLIC_ORIGIN` | `fly.toml` | `https://dev.site`. See above. |
| `DEVSITE_SIGNING_KEY` | `fly secrets` | Hex. Never in the repository. |
| `DEVSITE_BIND` | `Dockerfile` | `0.0.0.0:8080`, matching `internal_port`. |
| `DEVSITE_DB` | `Dockerfile` | `/data/devsite.db`, on the volume. |
| `DEVSITE_STATE_DIR` | `Dockerfile` | Unused while the secret is set. |
| `DEVSITE_WEB_ROOT` | `Dockerfile` | `/app/web`, baked into the image. |

## What Fly sees

Fly terminates TLS for the control plane, so it sees profile metadata and API calls — the
same position Cloudflare was in before. It never sees private service traffic: that goes
browser-to-daemon over an iroh relay, end-to-end encrypted, and the control plane is not
even told where the daemon is.

## Caching

`scripts/build-wasm.sh` publishes the wasm bundle under a content hash (`/pkg/<hash>/…`),
served `immutable`. The manifest naming the current hash, the HTML, and every `/api/`
response are `no-cache` or `no-store`. Redeploying therefore invalidates nothing and never
serves a stale bundle.

Cloudflare still holds the `dev.site` zone, but only as DNS — the `A` and `AAAA` records
point straight at Fly, unproxied.
