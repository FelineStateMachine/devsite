# Milestones

## M0 — Scaffolding ✅

Workspace, fixture server, Page A and Page B on 4101/4102.

## M1 — Transport spike ✅

Browser WASM endpoint ⇄ Iroh relay ⇄ daemon ⇄ loopback HTTP, address pasted in by hand.
Page A fetched in ~620 ms and rendered in a sandboxed iframe.

Findings:

- **`Connection::remote_id()` returns exactly the browser's endpoint id** — the primitive
  the capability binding rests on.
- **Cross-relay routing works.** Browser on `usw1-1`, daemon on `use1-1`, connection still
  established. The control plane can report whichever relay the daemon landed on.
- **`ring` needs a wasm-capable clang.** Apple's has no WebAssembly backend;
  `scripts/build-wasm.sh` finds Homebrew LLVM and sets `CC_wasm32_unknown_unknown`.
- `SecretKey::generate()` takes no RNG argument in iroh 1.0.

## M2 — Control plane ✅

Accounts, sessions, profiles, resource registration, sharing, daemon heartbeat/presence,
and profile rendering, all filtered through one `can_view` choke point. (The heartbeat and
presence half of that was removed in M8 — see below.)

Auth is **Shoo** (`https://shoo.dev`) — an OIDC broker that is **Google-backed, not
GitHub**, despite the initial assumption. Real OIDC: authorize + PKCE S256 in the browser,
ES256 `id_token`, JWKS at `/.well-known/jwks.json`, no client registration because
`client_id` is derived from the redirect origin as `origin:<origin>`.

Consequences worth remembering:

- **Account identity is pinned to the public origin.** `client_id` and `pairwise_sub` both
  derive from it, so changing `DEVSITE_PUBLIC_ORIGIN` orphans every existing account.
- The server verifies `aud == origin:<public origin>` exactly. Without that check, a token
  minted for any other Shoo site could be replayed here.
- The algorithm is pinned to ES256 rather than read from the token header.
- Shoo advertises RS256 and a `shooauth.com` JWKS URL on its marketing page; both are
  wrong. The working endpoints are all on `shoo.dev`. It is also labelled "SUPER EARLY WIP".

## M3 — Capabilities ✅

Ed25519 issuance at the control plane; the daemon verifies signature, audience, expiry,
**`browser_key` against `Connection::remote_id()`**, resource-in-local-config, permission,
and a nonce replay guard. Denials are opaque to the peer.

Findings:

- **The daemon must keep a connection open and loop over streams.** Serving one stream and
  dropping the connection leaves the peer holding a dead connection that its next request
  reuses — which surfaces as `connect` failing with "closed", not as anything obviously
  wrong on the daemon side.
- **The client must reuse one connection per daemon.** Dropping a `Connection` closes it,
  and the endpoint hands the same closed connection back to the next `connect` for that
  peer.
- **Failed attempts must not consume a capability's nonce**, or an observer could burn a
  viewer's single legitimate use.

## M4 — Sharing ✅

`--share @frank`, "shared with me" on the viewer's *own* profile only, Frank opens Page B.

## M5 — Negative tests ✅

`crates/devsite-daemon/tests/authz.rs`, over real Iroh against a real local service.

Two lessons the first draft got wrong:

- **`is_err()` is not an authorization assertion.** A relay timeout is also an error, so
  the negatives originally "passed" while the positives timed out. `FetchError` now
  separates `Denied` from `Transport`, and every negative asserts `Denied` specifically.
- **A `static` harness cannot be shared across `#[tokio::test]` functions.** Each gets its
  own runtime; the daemon's accept loop lives on whichever built the harness first, so once
  that runtime exits every later case hangs. The matrix runs as one test on one runtime.

## M6 — Live at https://dev.site ✅

Hosted behind Cloudflare Tunnel, so the control plane has no inbound port either. Two real
Google accounts signed in through Shoo; `@frank` opened `@dami`'s Agent and got Page B off
`127.0.0.1:4102`, while Hermes stayed absent from every listing and returned 404 on a
direct capability request by id.

Three bugs the live run found that the test suite had not:

- **Presence lied.** `online` meant "the owner's daemon is alive", not "this resource is
  reachable" — Agent advertised itself while the daemon did not serve it. Daemons now
  report the resource ids they serve on every heartbeat, and both the profile and
  `/api/capability` check membership.
- **Resource creation was not atomic with sharing.** `expose --share @frank` created the
  resource, then failed on the unknown handle, leaving an orphan no daemon served. Share
  targets are resolved before anything is written.
- **There were no migrations.** `CREATE TABLE IF NOT EXISTS` silently skips a new column on
  an existing database, and every read of it 500'd. There is now a `PRAGMA user_version`
  chain, with a test that opens a deliberately-old database.

Also: re-running `expose` used to create duplicate profile entries. It now upserts on
(owner, name), keeping the resource id stable so already-issued capabilities stay valid.

### Known rough edge

**The daemon reads its config only at startup.** Running `devsite expose` against a live
daemon has no effect until it restarts. It fails safe — the control plane reports the
resource offline rather than issuing capabilities for something unreachable — but config
hot-reload is the obvious fix.

## M7 — The profile page ✅

The first UI was a bespoke stylesheet: custom type, hand-drawn leaders, colour used as
meaning. It has been removed. The page is now semantic HTML styled by Pico CSS 2.1.1, set
in Open Sans at 400 and 700, both vendored so nothing is fetched from a third party.

The reason is not taste. `profiles.custom_css` was reserved for user styling from the
start, and user styling is only safe if "is this valid?" has a mechanical answer. Against
a bespoke stylesheet it does not: the answer depends on which class the author happened to
name and what it happened to do. Against Pico it does — the whole page is drawn from
`--pico-*` variables, so a theme can be a list of assignments to named variables with
per-property value grammars, checked in `theme.rs` and stored canonically.

What follows from that:

- **A theme has no selectors.** It cannot position, hide or overlay anything, and cannot
  make one profile impersonate another part of the site. It recolours and re-spaces the
  template; that is the whole of its power.
- **The theme block is the last stylesheet in the document**, so it wins ties on document
  order. No user declaration has to out-specify Pico, which is what a selector-based
  design would have forced.
- **The alphabet is the injection defence.** Every accepted value is `[0-9a-z#%.,/()+- ]`,
  so it cannot carry `<`, `"` or `}`. The rendered rule is safe to inline in `<style>` by
  construction rather than by remembering to escape it.
- **The whitelist is checked against the vendored Pico.** A variable Pico does not define
  would be accepted, stored, and silently do nothing — a bug with no error message.
- **Two weights, by construction.** Open Sans is a variable font here, declared twice at
  400 and 700 rather than as a range, so Pico's occasional request for 600 resolves to 700
  instead of rendering an in-between instance.

`GET /api/theme/properties` serves the list from the binary that enforces it, so the
website, `devsite theme properties` and the docs cannot drift from what is accepted.

See `docs/profile-template.md`.

## M8 — No heartbeat ✅

The daemon used to POST `/api/daemon/heartbeat` every 15 seconds, carrying its endpoint id,
its relay url, and the resource ids it served. All three are gone.

Reading iroh's `presets::N0` settles it. The preset installs a `PkarrPublisher` on the
daemon and a `PkarrResolver` on the viewer, and the resolver works **in the browser**, over
HTTPS to the n0 DNS server's `/pkarr` path — plain DNS is added only outside browsers. The
daemon was already publishing its own address and the browser could already resolve it. The
`with_relay_url()` in `connection_to` was feeding iroh something it would have found itself.

Taking the three fields in turn:

- **`relay_url`** was redundant, as above.
- **`endpoint_id`** is the public half of the key at `DEVSITE_HOME/identity`. It is the
  same on every run, so it is registered once when the daemon starts. `PUT /api/daemon`.
- **`serving` and `last_seen`** existed for the online/offline dot and a pre-flight refusal
  in `/api/capability`. The refusal was never a security property — the daemon checks
  resource-in-local-config on every request regardless, so removing the control-plane check
  makes nothing more permissive. And the dot was stale by up to 45 seconds; M6 records it
  lying outright.

So presence is gone entirely. A profile makes no claim about reachability, and clicking a
service finds out: `ViewerEndpoint::fetch` takes a bare endpoint id, lets iroh resolve it,
and bounds the attempt with `CONNECT_TIMEOUT`. "Offline" now means "we asked and nobody
answered", which is the only thing that was ever true.

What this bought:

- **Steady-state writes go to zero.** The database is read-mostly; the write path is a
  handful of rows per user per lifetime rather than 5,760 per daemon per day.
- **No timer on the user's machine**, and no 15-second wakeups against a laptop's radio.
- **The control plane is out of the addressing path**, which is what it always claimed.

The cost is honest and worth naming: a dead daemon takes `CONNECT_TIMEOUT` to report rather
than being greyed out in advance.

Verified in a browser against a real daemon: reached with only an endpoint id and no relay
url anywhere in the response, then killed the daemon and got the timeout and its message.

## M9 — Taking things back ✅

Everything could be created and nothing could be removed. `link add` and `expose` upsert on
`(owner, name, kind)`, so re-running either edited an entry in place — but a name typed
wrong was permanent, and there was no delete anywhere: no route, no command.

The worse half was sharing. `create_resource` never touched the `shares` table and
`share_with` was `INSERT OR IGNORE`, so the list only ever grew:

```
expose … --name Agent --share @bob      shares {bob}
expose … --name Agent --share @carol    shares {bob, carol}
```

The second command reads as "this is Carol's now". Bob kept access, `can_view` honoured the
stale row, and there was no way to remove it — a permission that could be granted and never
taken back. `set_shares` now replaces the list in a transaction, so naming nobody revokes.

`DELETE /api/resources/{id}` scopes the delete by owner in the statement itself rather than
checking first, so a request naming someone else's resource deletes nothing rather than
depending on a caller having asked the right question. Shares go with it by `ON DELETE
CASCADE` — which only started working when `foreign_keys` moved out of `SCHEMA` and into
every connection, in M8's Fly work. That pragma had been a no-op in every process that did
not create the database.

`devsite link remove <name>` and `devsite unexpose <name>` resolve the name to an id
client-side and delete by id. `unexpose` also drops the service from the local daemon
config, because a config that still lists it would re-register the name on the next
`expose`.

## Next

Surfaces that still have none: managing exposures from the website, and seeing who a
service is shared with. Renaming, too — remove and re-add is the only way, and for a
service that means a new resource id.
