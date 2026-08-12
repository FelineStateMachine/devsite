# Tickets

A ticket is a serializable object that packages the information required for an operation.
dev.site passes tickets between the browser, CLI, control plane, and daemon. Each ticket
type defines its own use count, lifetime, binding, storage, and revocation rules.

The control plane issues most tickets. It stores a SHA-256 hash for opaque bearer tickets.
It cannot recover their plaintext values. Signed tickets carry their own claims and signature.

## Ticket inventory

| Ticket | Purpose | Issuer | Consumer | Uses | Lifetime | Binding | Storage | Revocation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `dmt_…` | Enroll one machine | Control plane, at a signed-in user's request | CLI and control plane | One | Until enrollment or revocation | The enrolled machine endpoint after redemption | Control plane hash, then CLI input | Revoke the named machine entry before use |
| `dsm_…` | Authenticate one enrolled machine | Control plane after enrollment | CLI, daemon, and control plane | Many | No automatic expiry | Bearer ticket for one named machine. Enrollment and daemon registration also require endpoint proof. | CLI private `config.json`, control plane hash | Revoke the machine ticket |
| `dst_…` | Start one service connection | Control plane, at an authorised browser's request | `devsite connect` and control plane | One | Two minutes | One viewer and service. The session then binds to the client endpoint. | CLI input, control plane hash | Consume or expire the ticket. Removing access also prevents redemption. |
| `dss_…` | Request stream capabilities | Control plane after `dst_…` redemption or approved delegated access | Connector and control plane | Many | Eight hours. Delegated sessions last at most 15 minutes. | Client endpoint. Also tied to its issuer credential when delegated. | Connector memory, control plane hash | Delete or expire the session. Revoke its issuer credential, resource, account, or access. |
| `dsp_…` | Carry one reviewed delegated approval | Control plane signing key | Granting client and control plane | One grant for one request id | Limited by request and grant expiries | Request id, service, issuer ticket, resource, requester endpoint, and expiries | Caller-provided plan file or memory. It has no server-side plaintext row. | The ticket cannot create a grant after its request or grant expires. Revoke the issuer ticket or underlying access. |
| Stream ticket (signed capability) | Open one service stream | Control plane signing key | Daemon | One | Three minutes | Client endpoint, daemon endpoint, viewer, resource, and `TcpConnect` permission | Connector memory and stream handshake | Its nonce is consumed once. The daemon closes streams after access revocation or a stale authorisation snapshot. |
| Browser session | Keep a user signed in to the website | Control plane after sign-in | Browser and control plane | Many | Seven days | Bearer ticket with no endpoint-key binding | HttpOnly browser cookie and control plane hash | Log out or let the ticket expire |

## Machine enrollment ticket: `dmt_…`

A signed-in user creates a named `dmt_…` ticket on the dashboard. The ticket can carry
machine scopes such as `service_grants:issue`.

The CLI presents the ticket with a public endpoint key and proof from its matching private
key. The control plane atomically consumes the ticket, binds the machine entry to that
endpoint, and returns a `dsm_…` machine ticket.

`dmt_…` tickets have no automatic expiry. Create one when needed and use it promptly. A
leak can enroll one endpoint until use or revocation. Successful enrollment prevents reuse.

## Machine ticket: `dsm_…`

The `dsm_…` ticket lets the CLI and daemon make authenticated control-plane requests. It
does not travel over an Iroh service connection. Enrollment and daemon registration also
require proof from the persistent Ed25519 endpoint key.

The CLI stores this ticket in private `config.json`. The control plane stores only its hash.
Revoking it stops later authenticated use, unregisters its bound daemon, and deletes its
delegated tunnel sessions.

## Service connection ticket: `dst_…`

An authorised browser creates a `dst_…` ticket for one viewer and service. It expires after
two minutes. `devsite connect` creates a new Iroh endpoint key in memory and redeems the
ticket with that public endpoint id.

The control plane atomically deletes the ticket, checks current access, and returns a
client-bound `dss_…` tunnel ticket. The connector does not save it. It keeps the value only
in memory and deletes the session on a clean shutdown.

## Tunnel ticket: `dss_…`

A `dss_…` ticket lets one connector request a capability for each local TCP connection. An
ordinary connection ticket creates an eight-hour session. A delegated approval creates a
session that lasts at most 15 minutes.

The control plane binds the ticket to the client endpoint key. A delegated session also
links to the issuer credential. The control plane stores its hash and checks access before
it issues every capability.

## Approval ticket: `dsp_…`

A requester creates a signed request with an `agr_…` id, a service keyword, a temporary
endpoint, an expiry, and a private-key signature. The granting party asks the control plane
to resolve the request and issue a `dsp_…` ticket.

This ticket is a signed approval snapshot. It names the request id, service, issuer ticket,
chosen resource, requester endpoint, and expiries. The control plane verifies the request
proof again when it plans or applies the grant. The ticket cannot open a service stream.
Applying it creates at most one `dss_…` ticket for its request id.

The ticket has no server-side plaintext row. The caller can keep it in a plan file or
memory. Expiry, issuer-credential revocation, and access revocation stop a later grant.

## Stream ticket: signed capability

The connector uses a `dss_…` ticket to request one signed capability for one local TCP
connection. The control plane signs the capability with its private signing key. The daemon
pins the matching public key and uses it during the Iroh service handshake.

The ticket names the viewer, resource, client endpoint, daemon endpoint, and `TcpConnect`
permission. It expires after three minutes. The daemon accepts its nonce once and rejects a
different endpoint. It closes active streams when its authorisation snapshot is stale or no
longer permits the stream.

## Browser session ticket

A browser session ticket keeps a user signed in to the dashboard for seven days. The browser
stores it in an HttpOnly cookie. The control plane stores its hash. Logout or expiry ends
its use.

## Tickets and secrets

Treat complete `dmt_…`, `dsm_…`, `dst_…`, and `dss_…` values, browser cookies, and live
signed capabilities as secrets. Redact them from logs, screenshots, shell history, and agent
transcripts.

Keep a `dsp_…` ticket inside its approval workflow. It cannot open a connection by itself,
but it records a reviewed decision. `acct_…`, `res_…`, `machine_…`, `agr_…`, handles, and
endpoint ids are identifiers. They do not grant access by themselves.

See [Keys and endpoint identities](keys-and-identities.md) for the private keys that bind
some tickets to Iroh endpoints.
