# ALPN and the service wire protocol

dev.site currently defines one application protocol for service traffic:

| ALPN | Purpose | Transport |
| --- | --- | --- |
| `devsite/tcp/1` | Authorize and carry arbitrary TCP byte streams | Iroh QUIC, direct or relayed |

ALPN means Application-Layer Protocol Negotiation. During the QUIC/TLS handshake, the
client requests `devsite/tcp/1` and the daemon advertises that exact value. This selects the
wire protocol before either side interprets an application frame.

## Where it fits

The dev.site control plane and service path are separate:

```text
CLI ── HTTPS ──► dev.site control plane
 │               session validation + capability issuance
 │
 └── Iroh QUIC, ALPN devsite/tcp/1 ──► owner's daemon ── TCP ──► loopback service
               encrypted service bytes
```

`devsite/tcp/1` is not the protocol used by the HTTPS API, OIDC login, the local MCP stdio
adapter, or the hosted application. The application behind a service can speak PostgreSQL,
HTTP, SSH, Redis, or any other TCP protocol; after authorization, dev.site treats its bytes
as opaque.

## One connection and one stream

The client keeps one authenticated QUIC connection per daemon and can open many
bidirectional streams on it. Each forwarded local TCP connection uses a new QUIC stream:

1. The client opens a bidirectional stream.
2. It sends one length-prefixed Postcard `Connect` request containing a signed capability.
3. The daemon verifies the control-plane signature, daemon audience, authenticated client
   endpoint, expiry, permission, resource, and one-use nonce.
4. The daemon connects to the resource's fixed loopback TCP target.
5. It sends `Connected`, or a deliberately coarse error.
6. After `Connected`, both sides copy uninterpreted TCP bytes until half-close or shutdown.

The control plane is contacted to mint the capability, but it is not on this data path and
never sees the service bytes or local target port.

## Frame format

The request and response each use this envelope:

```text
4-byte little-endian payload length
Postcard-encoded payload
```

The length is checked before allocation and may not exceed 4 MiB. Version 1 has one request
variant, `Connect { capability }`, and these responses:

- `Connected`;
- `Error { Denied }` for invalid authorization, unknown resources, or capability replay;
- `Error { BadRequest }` for malformed protocol input; and
- `Error { UpstreamUnavailable }` when the configured local TCP service does not accept a
  connection.

Authorization failures intentionally collapse to `Denied`. A remote peer cannot use error
differences to discover whether a resource exists, whether it is hosted, or which
capability check failed.

Once `Connected` is sent, there are no more dev.site frames on that stream. Everything
after it is the service's raw byte stream.

## Security properties

Iroh QUIC encrypts the network and authenticates endpoint public keys. The capability then
adds application authorization:

- its server signature identifies the control plane that issued it;
- its audience binds it to one daemon endpoint;
- its client key must match the connection's authenticated remote endpoint;
- its resource maps only to a fixed loopback target configured by the host;
- its permission is currently only `TcpConnect`;
- its expiry limits it to three minutes; and
- its nonce is accepted only once by the daemon.

ALPN contributes protocol separation and version selection, not user authorization. A
client that negotiates `devsite/tcp/1` still gets no service access without a valid
capability. Conversely, capability bytes sent under some other protocol are never parsed
as a dev.site request.

Iroh may establish a direct path or use a relay. Relays carry encrypted QUIC traffic and do
not terminate the dev.site application stream. The final daemon-to-service hop is local TCP
on the host and uses whatever encryption, if any, the service protocol provides.

## Versioning

The `/1` suffix is a compatibility boundary for framing and semantics. A change that old
peers cannot safely decode or interpret should use a new ALPN rather than silently changing
version 1. The current client requests one ALPN and the daemon advertises one ALPN; there is
no dev.site protocol fallback or multi-version negotiation today.

The public `/api/config` response reports the expected daemon protocol. `devsite doctor`
compares it with the CLI's compiled `devsite/tcp/1` value so a control-plane/client mismatch
is visible before debugging the data path.

Adding another ALPN should define its exact request and response frames, authorization
checks, maximum sizes, transition from framing to application bytes, compatibility policy,
and diagnostic behavior. A new service application protocol alone does not require a new
ALPN because version 1 already transports arbitrary TCP bytes.
