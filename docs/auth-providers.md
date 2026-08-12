# Authentication providers

dev.site has one authentication boundary: a provider proves an external identity, then the
application turns that identity into its own account and browser session. Shoo is the default
OIDC configuration, not part of the account, sharing, CLI, or capability model.

```text
provider-specific login
        │ verify credentials, callback, issuer and subject
        ▼
ExternalIdentity { namespace, subject }
        │ establish_browser_session
        ▼
dev.site AccountId + opaque HttpOnly session
```

The stable types and functions are:

- `auth::ExternalIdentity` in `crates/devsite-server/src/auth.rs`.
- `api::establish_browser_session` in `crates/devsite-server/src/api.rs`.
- `api::browser_session_cookie`, which applies the dev.site cookie policy.

The application port deliberately is not an OAuth-shaped trait. An OIDC callback, a passkey,
a signed proxy header, and a local enterprise SSO flow have different HTTP exchanges. Each
inbound adapter owns that exchange and ends by producing the same small `ExternalIdentity`.

## Use another OIDC provider

The built-in adapter implements authorization code flow with PKCE S256. The browser enters at
`GET /auth/start`; the server stores a short-lived verifier, redirects to the provider, handles
`GET /auth/callback`, exchanges the code, verifies the ID token against JWKS, and then calls the
application port. No provider token reaches browser JavaScript.

The replacement provider must support:

- a public client using authorization code flow and PKCE S256;
- a token endpoint that accepts `token_endpoint_auth_method=none`;
- an ID token containing `iss`, `sub`, `aud`, and `exp`;
- a JWKS endpoint and an asymmetric JWT signing algorithm.

Client-secret authentication is intentionally not implemented. Configure a public client, or
add secret handling to the adapter without exposing the secret through `/api/config` or the web
application.

Register this exact callback at the provider:

```text
<DEVSITE_PUBLIC_ORIGIN>/auth/callback
```

Then configure the adapter. Discovery is not automatic; endpoints are explicit so startup does
not silently trust metadata from somewhere other than the configured issuer.

| Variable | Default |
| --- | --- |
| `DEVSITE_OIDC_ISSUER` | `https://shoo.dev` |
| `DEVSITE_OIDC_AUTHORIZATION_ENDPOINT` | `<issuer>/authorize` |
| `DEVSITE_OIDC_TOKEN_ENDPOINT` | `<issuer>/token` |
| `DEVSITE_OIDC_JWKS_URI` | `<issuer>/.well-known/jwks.json` |
| `DEVSITE_OIDC_CLIENT_ID` | `origin:<DEVSITE_PUBLIC_ORIGIN>` |
| `DEVSITE_OIDC_SCOPES` | `openid` |
| `DEVSITE_OIDC_ALGORITHMS` | `ES256` |

For example:

```bash
export DEVSITE_PUBLIC_ORIGIN=https://devsite.example.com
export DEVSITE_OIDC_ISSUER=https://identity.example.com/realms/developers
export DEVSITE_OIDC_AUTHORIZATION_ENDPOINT=https://identity.example.com/realms/developers/protocol/openid-connect/auth
export DEVSITE_OIDC_TOKEN_ENDPOINT=https://identity.example.com/realms/developers/protocol/openid-connect/token
export DEVSITE_OIDC_JWKS_URI=https://identity.example.com/realms/developers/protocol/openid-connect/certs
export DEVSITE_OIDC_CLIENT_ID=devsite
export DEVSITE_OIDC_SCOPES='openid profile email'
export DEVSITE_OIDC_ALGORITHMS=RS256

cargo run -p devsite-server
```

Provider URLs must use HTTPS. HTTP is accepted only for a loopback provider during local
development. `openid` must remain in the scope list, symmetric `HS*` algorithms are rejected,
and every accepted token must match the configured issuer and client ID exactly.

To smoke-test initiation without completing a login:

```bash
curl -i 'http://127.0.0.1:4000/auth/start?return_to=%2F'
```

Expect a `307` response whose `Location` points at the configured authorization endpoint and a
callback-scoped `devsite_login_state` cookie. Complete a browser login before considering the
provider verified; that exercises code exchange, JWKS retrieval, claims validation, account
lookup, and session creation together.

### Identity continuity

An account is keyed by the exact `(namespace, subject)` pair. For OIDC these values are the
verified `iss` and `sub` claims. Changing the issuer string, client configuration in a provider
that issues pairwise subjects, or the subject itself creates a different dev.site account.

Never substitute email, handle, display name, or another mutable claim for `sub`. Never label a
new provider with the old provider's namespace merely to preserve accounts: that would let the
new provider impersonate every old identity. Continuity across unrelated providers requires an
explicit, authenticated account-linking or operator migration design.

Existing databases are migrated as follows:

- old Shoo subjects become `("https://shoo.dev", <old subject>)`;
- operator-issued identities become `("local", <handle>)`.

## Implement a non-OIDC provider

Use `crates/devsite-server/src/oidc.rs` as the reference inbound adapter, but keep only the
security mechanisms appropriate to the new protocol. The implementation path is:

1. Add a module under `crates/devsite-server/src/`, for example `passkey.rs`.
2. Give it the provider-owned start, challenge, and callback routes.
3. Verify the provider proof completely inside that module.
4. Construct `ExternalIdentity` only after verification succeeds.
5. Call `api::establish_browser_session` with that identity.
6. Put the returned token into `api::browser_session_cookie` and redirect to a local path.
7. Wire the adapter router in `main.rs`, replacing `oidc::router(...)`.
8. Keep `/auth/start` as the browser entrypoint so `web/app.js` remains provider-neutral.

A callback ends approximately like this:

```rust,ignore
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};

use crate::api::{self, Shared};
use crate::auth::ExternalIdentity;

fn finish_login(
    app: &Shared,
    verified_provider_user_id: String,
    return_to: &str,
) -> Response {
    // This namespace is a permanent identity boundary. Do not accept it from the request.
    let identity = ExternalIdentity {
        namespace: "passkey:https://devsite.example.com".to_string(),
        subject: verified_provider_user_id,
    };

    let session = match api::establish_browser_session(app, identity) {
        Ok(session) => session,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let target = if session.handle.is_some() { return_to } else { "/" };
    let mut response = Redirect::to(target).into_response();
    let cookie = api::browser_session_cookie(app, &session.token);
    match HeaderValue::from_str(&cookie) {
        Ok(cookie) => {
            response.headers_mut().append(header::SET_COOKIE, cookie);
            response
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
```

The namespace must be hard-coded or trusted configuration, globally unambiguous, and stable for
the lifetime of the installation. The subject must be a stable, provider-assigned identifier and
is limited to 2048 bytes. The database automatically creates or reuses the corresponding account;
a new provider namespace does not require another schema migration.

### Wiring

The current OIDC wiring in `main.rs` does three things that a replacement must preserve:

1. constructs and validates adapter configuration before listening;
2. exposes the active identity namespace in `AppState.identity_namespace` and `/api/config`;
3. merges the adapter routes into the Axum application.

The corresponding `main.rs` shape is:

```rust,ignore
mod passkey;

let login = passkey::Config::from_env(&config.public_origin)?;
let identity_namespace = login.namespace().to_string();

let state = Arc::new(AppState {
    // Existing database, rate limiter, capability issuer, and public origin fields...
    identity_namespace,
});

let app = api::router(Arc::clone(&state))
    .merge(passkey::router(Arc::clone(&state), login)?);
```

For one replacement provider, change the module and router construction in one place. The current
UI advertises one `auth.start_url`, so supporting several providers simultaneously additionally
requires a provider list in `/api/config` and a provider picker in `web/app.js`. The account table
already supports multiple namespaces.

### Security contract for a new adapter

Before handing an identity to the application port, an adapter must:

- authenticate the proof cryptographically or through a trusted back channel;
- bind callbacks to the browser that started them and consume challenges once;
- reject expired, replayed, wrong-audience, and wrong-origin proofs as applicable;
- derive `namespace` from trusted configuration, never request data;
- use a stable opaque subject, never email or a display name;
- validate local return paths before placing them in a `Location` header;
- keep credentials, codes, assertions, and provider tokens out of logs and browser storage;
- return indistinguishable public errors for invalid identities while logging useful server-side
  context without secrets;
- bound temporary state, credential sizes, and outbound request timeouts.

Provider logout is separate from dev.site logout. `DELETE /api/auth/session` always revokes the
local session. An adapter may add upstream logout, but local revocation must succeed even when the
provider is unavailable.

### Tests to add

At minimum, cover:

- a valid proof produces the expected namespace and subject;
- invalid signatures or credentials never reach `establish_browser_session`;
- challenge/state mismatch, expiry, and replay are rejected;
- the same `(namespace, subject)` reuses an account;
- the same subject in two namespaces creates two accounts;
- unsafe return paths cannot redirect off-site;
- provider outages time out and do not create sessions.

Run the repository checks before deploying:

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo build --release --locked -p devsite-server
node --check web/app.js
```
