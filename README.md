# dev.site

A developer profile that mixes ordinary public links with private, locally-hosted services —
reachable from a browser without deploying those services or opening a port.

Status: **Live at https://dev.site.** The full vertical slice works end to end — public
links, owner-private local services, person-to-person sharing, centralized authorization,
browser access over an encrypted relay, and no port forwarding anywhere. Verified with two
real Google accounts. See `docs/milestones.md`.

## How it works

```
browser (ephemeral Iroh key)
   │  1. POST /api/capability {resource_id, browser_endpoint_id}
   ▼
dev.site control plane ── authorizes, signs a short-lived capability (Ed25519)
   │  2. {capability, daemon endpoint id}
   ▼
browser ──── 3. Iroh, end-to-end encrypted via relay ────► your daemon
             (address resolved from the daemon's own
              published record, not from dev.site)
                                                              │ 4. verify
                                                              ▼ signature · audience ·
                                                                expiry · browser key vs
                                                                the authenticated peer ·
                                                                resource in local config
                                                           127.0.0.1:4101
```

The browser never names an upstream URL. The daemon resolves the origin from its own
config, keyed by resource id — that is what keeps it from being an open proxy. The control
plane holds permissions but never carries service traffic.

It is not a directory either. It stores a daemon's endpoint id — written once, because the
id is the public half of a key on disk and does not change — and nothing about where that
endpoint is or whether it is up. Iroh already answers both: the daemon publishes its own
address, and the browser resolves it over HTTPS. There is no heartbeat and no presence
service. Whether a service is running is discovered by asking it.

## Prerequisites

- Rust stable + `rustup target add wasm32-unknown-unknown`
- `cargo install wasm-pack`
- A clang with the WebAssembly backend (`ring` compiles C). Apple's system clang does not
  have one — on macOS run `brew install llvm`. `scripts/build-wasm.sh` finds it.

## Running it locally

```bash
./scripts/build-wasm.sh

export DEVSITE_PUBLIC_ORIGIN=http://127.0.0.1:4000   # pins account identity, see below
cargo run -p devsite-server

cargo run -p devsite-fixture -- 4101 fixtures/page-a.html   # Hermes
cargo run -p devsite-fixture -- 4102 fixtures/page-b.html   # Agent
```

Sign in at <http://127.0.0.1:4000> (Google, via Shoo), or mint a session from the shell:

```bash
cargo run -p devsite-server -- issue-session alice
```

Then configure the machine:

```bash
devsite login --token <token>
devsite profile create @alice
devsite link add --name "Klot Ski" --url https://klot.ski --public
devsite expose http://127.0.0.1:4101 --name "Hermes" --private
devsite expose http://127.0.0.1:4102 --name "Agent" --share @bob
devsite theme set my-theme.css
devsite daemon run
```

Re-running `link add` or `expose` with the same name edits that entry in place, and
the share list it names replaces whatever was there — `--share @carol` means the
resource is Carol's, not Carol's as well. To take something down:

```bash
devsite link remove "Klot Ski"
devsite unexpose Hermes
```

### The profile page

Semantic HTML styled by [Pico CSS], set in Open Sans at 400 and 700. Both are
vendored under `web/vendor/`, so the page makes no third-party request.

Personalisation is real CSS, but not a stylesheet: a theme is a list of
assignments to named Pico variables, each checked against a declared value
grammar before it is stored. No selectors, no properties, no `!important` — so a
theme can recolour and re-space the page and can do nothing else. The template it
applies to, the whitelist, and the grammars are in
[`docs/profile-template.md`](docs/profile-template.md).

[Pico CSS]: https://picocss.com

### Configuration

| Variable | Default | Notes |
| --- | --- | --- |
| `DEVSITE_PUBLIC_ORIGIN` | *(required)* | The exact origin browsers load. **Changing it orphans every account** — Shoo derives both `client_id` and the pairwise subject from it. |
| `DEVSITE_BIND` | `127.0.0.1:4000` | |
| `DEVSITE_DB` | `devsite.db` | |
| `DEVSITE_STATE_DIR` | `.devsite-state` | Holds the capability signing key, when it is not supplied directly. |
| `DEVSITE_SIGNING_KEY` | *(unset)* | The capability signing key as 64 hex characters. Takes precedence over the state directory; a bad value is fatal rather than a reason to generate a new key. For hosts where a secret store beats a file. |
| `DEVSITE_HOME` | platform config dir | Daemon identity and config. Set it to run several daemons on one machine. |

## Deploying

The control plane runs on Fly: one machine, one volume, SQLite on it. `fly.toml` and
`Dockerfile` are the deployment; `fly deploy` builds both the wasm bundle and the binary
inside the image, so nothing is uploaded from a laptop.

```bash
fly deploy
```

Two settings cannot be undone — the public origin, and the capability signing key, which is
a Fly secret rather than a file so that losing a volume does not lose every daemon's trust.
First-time setup, DNS, certificates and backups are in
[`deploy/README.md`](deploy/README.md).

## Layout

| Path | What it is |
| --- | --- |
| `crates/devsite-proto` | Ids, capability token, wire frames. No I/O; compiles for wasm. |
| `crates/devsite-client` | Viewer side of the data plane. Compiles native **and** wasm. |
| `crates/devsite-web` | wasm-bindgen seam over `devsite-client`. |
| `crates/devsite-daemon` | Iroh endpoint, capability verification, loopback proxy. |
| `crates/devsite-server` | Control plane: axum + SQLite, Shoo auth, capability issuance. |
| `crates/devsite-cli` | `devsite` — login, profile, link, expose, unexpose, theme, daemon run. |
| `crates/devsite-fixture` | Serves one HTML file on a port; stands in for a real service. |
| `web/` | The site. `web/vendor/` is Pico and Open Sans; `web/pkg/` is generated by `scripts/build-wasm.sh`. |

`devsite-client` compiling both ways is deliberate: the authorization matrix is proven by
fast native tests running the exact code the browser executes.

## Testing

```bash
cargo test --workspace
```

75 tests. The interesting ones are `crates/devsite-daemon/tests/authz.rs`, which drives
real Iroh against a real local service and asserts that forged, expired, misaddressed,
rebound, replayed and unknown-resource capabilities are each refused — and that a denial
tells the caller nothing about which of those it was. `theme.rs` carries the other
adversarial set: a theme that tries to become a stylesheet, escape its rule, or name a
property outside the whitelist.

## Security notes

- Capabilities are bound to a browser endpoint key and checked against the connection's
  authenticated peer, so a stolen capability is useless without the matching private key.
- Denials are deliberately indistinguishable from one another, and `/api/capability`
  returns 404 rather than 403, so resource ids cannot be enumerated.
- `devsite expose` refuses public addresses: exposures are limited to loopback, private
  ranges and `.ts.net`, so a daemon cannot be turned into a launderer for its owner's IP.
- Fetched pages render in `sandbox="allow-scripts"` **without** `allow-same-origin`, giving
  them an opaque origin with no access to dev.site's DOM, storage or cookies.
- A profile theme is a whitelist of Pico variables with per-property value grammars, so
  the alphabet of a stored value cannot contain `<`, `"` or `}`. User styling cannot
  position, hide or overlay anything, and cannot make one profile impersonate another.
- A share names the whole list, so `--share @carol` revokes whoever was named before rather
  than adding to them, and sharing with nobody takes it back entirely.
- Deletes are scoped by owner inside the statement, not by a check beforehand, so a request
  naming someone else's resource removes nothing.
- Session tokens are stored only as SHA-256 hashes.
- `issue-session` is an operator command requiring shell access; there is no
  network-reachable authentication bypass.
