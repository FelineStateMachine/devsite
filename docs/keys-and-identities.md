# Keys and endpoint identities

dev.site uses Ed25519 keys for three jobs: identifying Iroh endpoints, proving that a
request came from the endpoint it names, and signing control-plane authorization. A
public endpoint id is safe to share. Its matching private key is what proves possession.

## Key inventory

| Key | Lifetime and storage | What it proves |
| --- | --- | --- |
| Machine endpoint key | Persistent; `devsite-endpoint.key` in the dev.site config directory | The enrolled machine and its daemon are the same endpoint |
| Machine endpoint public key | Persistent; `devsite-endpoint.pub` and the endpoint id registered with the server | Where to address the daemon and which key capabilities name as their audience |
| Ordinary connector key | Ephemeral; process memory only | Which client redeemed a `dst_…` ticket and opened the Iroh connection |
| Delegated requester key | Temporary; a caller-selected file such as `requester.key` | Which endpoint signed the request and may use the resulting grant |
| Control-plane signing key | Persistent operator secret; environment secret or `capability_signing.key` | That a plan or stream capability was issued by this control plane |
| Pinned control-plane public key | Persistent; stored in the machine's private `config.json` | Which control-plane signatures the daemon will trust |

All are 32-byte Ed25519 private keys or their public halves. A displayed Iroh endpoint id
is the encoded public key, not a separate secret identifier.

## Persistent machine endpoint identity

The CLI creates the machine endpoint key during first login or daemon startup and keeps it
across restarts:

```text
dev.site config directory/
├── devsite-endpoint.key   private, raw 32 bytes
├── devsite-endpoint.pub   public endpoint id, text
└── config.json            private machine credential + pinned server public key
```

Set `DEVSITE_HOME` to choose the config directory explicitly. Otherwise the CLI uses the
operating system's application config location. On Unix, private files are created with
mode `0600`; the public `.pub` file does not need private permissions.

During enrollment, the CLI signs a domain-separated endpoint-proof message. The server
checks that proof before binding the returned machine credential to the public endpoint id.
Daemon registration repeats a possession proof. A scoped granting party also uses this
same key to sign the chosen resource, requester endpoint, request id, and grant expiry.

Capabilities sent to this daemon name its public endpoint key as the audience. The daemon
rejects a capability issued for another endpoint even if every other claim is valid.

### Prepare for version 0.6.0

Before you upgrade to version 0.6.0, run `devsite login` or `devsite daemon run` with an
earlier version. That version moves `identity.key` and `identity.pub` to the new names.

The earlier version checks only these exact names in the resolved dev.site config directory.
It does not scan the current directory, home directory, SSH directory, or filesystem for
similar names.

The earlier version moves a legacy file only when the target file does not exist:

```text
identity.key  → devsite-endpoint.key
identity.pub  → devsite-endpoint.pub
```

An existing `devsite-endpoint.key` or `devsite-endpoint.pub` takes priority. Version 0.6.0
does not read or move `identity.key` or `identity.pub`.

## Client endpoint keys

For ordinary `devsite connect dst_…`, the CLI creates a fresh Iroh key in memory. The
public half is supplied when the ticket is redeemed, the resulting `dss_…` session is
bound to it, and every per-stream capability repeats that binding. The daemon compares the
capability's client key with the authenticated remote endpoint from the QUIC connection.
A copied session or capability is therefore insufficient without the private key.

The key disappears when the connector process exits. A new process cannot resume that
session, even if it has copied the `dss_…` ticket.

## Delegated requester keys

`devsite access request` creates a temporary requester key in a caller-selected file:

```sh
devsite access request postgres \
  --request request.json \
  --key requester.key
```

Both paths are created without overwriting existing files and use private permissions on
Unix. The request JSON contains the public endpoint id and a signature over the request id,
service keyword, endpoint id, and expiry. Only `request.json` should cross the sandbox or
approval boundary. `requester.key` stays with the requester and is later supplied to
`devsite access connect`.

The key file itself does not expire, but every request and resulting session does. Delete
it after the request and any granted connection are finished. If the key leaks while a
grant is active, revoke the issuing machine credential or underlying service access and
stop the connector; waiting for the grant's 15-minute maximum lifetime also bounds the
exposure.

## Control-plane signing key

The control plane has one Ed25519 signing key shared by two authorization formats:

- `dsp_…` service-grant approval plans; and
- one-stream service capabilities.

Production can supply the private key through `DEVSITE_SIGNING_KEY`. A local deployment
without that setting loads or creates `capability_signing.key` in the server state
directory with private permissions. The private key must never be distributed to clients
or daemons.

At login, the CLI fetches the public half from `/api/pubkey` and pins it in `config.json`.
The daemon refuses to start without a valid pinned key and verifies every capability
against it. `devsite doctor` compares the currently published server key with the pinned
value and reports a change rather than silently trusting it.

Losing the private signing key prevents the server from minting artifacts that existing
daemons trust. Compromise permits forging plans and capabilities until clients move to a
new trust root. Back it up as an operator secret and treat rotation as an explicit
re-enrollment or re-pinning event, not a routine file replacement.

## What compromise permits

| Compromised material | Consequence | Recovery |
| --- | --- | --- |
| Machine endpoint private key only | Endpoint impersonation is possible, but control-plane API calls still require the machine credential | Revoke the named machine credential, remove the key, and enroll a new endpoint |
| Machine credential only | Authenticated control-plane actions within its scopes; it cannot satisfy endpoint proofs without the key | Revoke the named machine credential and log in again |
| Machine key and credential | Full authority of that enrolled machine and its scopes | Revoke immediately and re-enroll with a new key |
| Ephemeral connector key | Useful only with its still-live bound session or capability | Stop the connector/delete its session; ordinary key vanishes with the process |
| Delegated requester key | Use of a still-live grant bound to that requester | Stop/revoke the grant path and delete the key |
| Control-plane signing key | Forged approval plans and service capabilities | Rotate the trust root and re-pin or re-enroll every daemon |

A `dsm_…` machine ticket is a bearer ticket, not a cryptographic key, even though the CLI
stores it beside key material. See [Tickets](tickets.md) for its lifecycle.
