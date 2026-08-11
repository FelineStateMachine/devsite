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
and profile rendering, all filtered through one `can_view` choke point.

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

## Next

Surfaces that still have none: managing exposures from the website, and seeing who a
service is shared with.
