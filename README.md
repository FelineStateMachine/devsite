# dev.site

[dev.site](https://dev.site) puts links and private TCP services on one developer profile.
Services stay on the machines that own them. An approved user maps a service onto a local
loopback port with the `devsite` CLI.

The control plane handles identity, profiles, sharing, and short-lived capabilities. It
never carries service traffic. Hosts make outbound Iroh connections, so there is no public
listener or inbound port to configure.

Version 0.2.0 replaces the early single-page HTTP fetch experiment. Services are
protocol-agnostic TCP byte streams; they are not assumed to be websites.

## Install

macOS with [Homebrew](https://brew.sh):

```bash
brew install FelineStateMachine/tap/devsite
```

Linux binaries and other builds are attached to the
[latest GitHub release](https://github.com/FelineStateMachine/devsite/releases/latest).
The CLI is one binary; `devsite daemon run` is its long-running host mode.

## Quick start

Sign in at [dev.site](https://dev.site), create a machine credential on the dashboard, and
use the one-time value to log in:

```bash
devsite login dsm_...
```

Host a named local service and keep the daemon running:

```bash
devsite service host 5432 --name postgres
devsite daemon run
```

Approve a share on the dashboard, open the service, and choose **Get ticket**. On the
viewer machine:

```bash
devsite connect dst_...
# connected to postgres (https://dev.site/s/res_...)
#   listening on 127.0.0.1:43127
```

## Shape

```text
viewer application
      │ TCP to 127.0.0.1:ephemeral
      ▼
devsite connect
      │ capability-gated Iroh QUIC stream
      ▼
owner's devsite daemon
      │ TCP to 127.0.0.1:PORT
      ▼
private service

dev.site control plane ── identity, profiles, approved shares, capability signing
```

The control plane never carries service bytes and never learns the local port. It stores
resource metadata and permissions, mints browser-requested connection tickets, then signs
one short-lived capability per connection.
The daemon verifies the signature, daemon audience, client endpoint key, resource id,
expiry, and one-use nonce before opening the configured loopback target.

The transport ALPN is `devsite/tcp/1`.

## Services and links

Services default to private:

```bash
devsite service host 3000
# hosting port 3000 → 127.0.0.1:3000 (private)
#   https://dev.site/s/res_...
```

Names and folders are presentation. Hosted ports enter the `Services` folder unless a
different folder is named:

```bash
devsite service host 5432 --name postgres --folder databases
```

Sharing remains per service. A recipient must approve the invitation on their dashboard:

```bash
devsite service host 6379 --name redis --folder databases --share @bob
```

A permitted viewer opens the service on dev.site, clicks **Get ticket**, and passes the
single-use ticket to the CLI. Viewer machines do not need a saved login:

```bash
devsite connect dst_...
# connected to postgres (https://dev.site/s/res_...)
#   listening on 127.0.0.1:43127
```

Choose a stable local port when an application expects one:

```bash
devsite connect dst_... --listen 127.0.0.1:15432
psql -h 127.0.0.1 -p 15432
```

The connector refuses non-loopback listeners. Stop hosting a service with:

```bash
devsite service remove postgres
```

Links default to private, can be shared for recipient approval, or made public:

```bash
devsite link set --name runbook --url https://example.com/runbook
devsite link set --name staging --url https://staging.example.com --share @bob
devsite link set --name klot.ski --url https://klot.ski --public --folder Games
```

Setting an existing link or hosting an existing service prints the visibility, recipient,
destination, and folder changes before applying the upsert. Changing a shared link's URL
requires its recipients to approve the new destination again.

## Daemon

`devsite daemon run` is the portable foreground service entrypoint. A service manager only
needs to keep that command alive:

```bash
devsite daemon run
```

Every command accepts `--json` for automation. Finite commands emit one success or error
object; `connect` and `daemon run` emit newline-delimited lifecycle events. JSON mode never
prompts. Command-specific `--help` is available as structured JSON, and failures include a
recovery suggestion. The complete stdout and exit-code contract is in
[`docs/json-output.md`](docs/json-output.md).

Homebrew installs can supervise it at login on macOS or Linux:

```bash
brew services start devsite
```

Native Linux packages may install `packaging/systemd/devsite.service` as a user unit:

```bash
systemctl --user enable --now devsite.service
```

The endpoint identity persists in the devsite config directory. The daemon registers that
public endpoint id with the control plane once at startup, publishes its address through
Iroh, and reloads service targets from the local config every two seconds. Adding or
removing a service does not require restarting it.

`devsite daemon status` reports whether this config directory has a live daemon. The same
liveness appears in `devsite status` alongside the config location, pinned signing key, and
locally served ports. The lock is released by the operating system on exit, so a crash does
not leave a stale running state.

## Profiles and folders

A profile is a list of ordinary links and TCP services. Folders are repeated labels on
entries and exist only to group the UI; they are not authorization containers. Accepted
shares appear as ordinary rows in those folders with their owner noted, not in a separate
top-level sharing section. Every site retains its own visibility, invitation state, and
revocation; services additionally enforce access for every tunnel connection.

The signed-in homepage is the dashboard. It manages approved and pending shares, revocable
machine credentials, the private-only profile setting, and logout. Themes remain a bounded
list of approved Pico CSS variables rather than arbitrary CSS.

## Local development

Prerequisite: stable Rust.

```bash
export DEVSITE_PUBLIC_ORIGIN=http://127.0.0.1:4000
cargo run -p devsite-server
```

For operator-only setup, mint a local browser session:

```bash
cargo run -p devsite-server -- issue-session alice
```

Build and test everything:

```bash
cargo test --workspace
cargo build --release -p devsite-cli
```

## Deployment

The control plane runs as one Fly machine with one attached volume and SQLite behind a
mutex. `fly.toml` and `Dockerfile` describe it:

```bash
fly deploy
```

The traffic path scales independently because it does not pass through Fly. Iroh relays
carry end-to-end encrypted QUIC between clients and daemons; the control plane only signs
authorization metadata.

The two durable identities are `DEVSITE_PUBLIC_ORIGIN`, which Shoo uses when deriving
accounts, and `DEVSITE_SIGNING_KEY`, whose public half every daemon pins at login. Changing
either is intentionally disruptive.

## Crates

| Path | Responsibility |
| --- | --- |
| `crates/devsite-proto` | Opaque ids, signed capabilities, and the TCP stream handshake. |
| `crates/devsite-client` | Native Iroh viewer endpoint and authorized service streams. |
| `crates/devsite-daemon` | Capability verification and fixed-target TCP forwarding. |
| `crates/devsite-cli` | Login, links, service hosting/connect, themes, and daemon lifecycle. |
| `crates/devsite-server` | Axum/SQLite control plane and capability issuance. |
| `web/` | Semantic HTML, plain JavaScript, Pico CSS, and vendored fonts. |

## Security boundaries

- A peer supplies only a signed capability. It never supplies the daemon's target address.
- `devsite service host PORT` always stores `127.0.0.1:PORT`; port zero is rejected.
- `devsite connect` listens only on a loopback address.
- Browser-minted tickets are short-lived, stored only as hashes, and consumed once. A
  successful redemption becomes a client-key-bound tunnel session kept only in CLI memory.
- Capabilities are bound to the authenticated Iroh client endpoint and cannot be replayed
  by another endpoint.
- Each capability opens one stream and its nonce is consumed once.
- Unknown resources, invalid signatures, wrong audiences, wrong clients, expiry, and replay
  all produce the same denial.
- Service identifiers are locators, not bearer credentials. Visibility and accepted-share
  state are checked whenever a new capability is requested.
- The control plane rate-limits capability issuance and bounds profiles, names, links,
  folders, credentials, and share lists.
- Machine credentials and browser sessions are stored only as SHA-256 hashes and can be
  revoked from the dashboard.

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
