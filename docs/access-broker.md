# Delegated endpoint access

Delegated access lets a sandboxed worker obtain narrowly bounded service access without
giving that worker a person's browser session, a machine credential, or the granting
machine's endpoint key.

## Actors and authority

- The **requester** owns a fresh, temporary Ed25519 endpoint key and creates a signed service
  request. Its public request is safe to hand to the granting party; its private key is not.
- The **granting party** is a human or automated process operating an ordinary enrolled
  machine whose single-use enrollment ticket carried the `service_grants:issue` scope. The
  server stores that scope on the resulting revocable machine credential.
- The **control plane** verifies both signatures, enforces the grant scope and account
  permissions, rejects replays, and issues an endpoint-bound tunnel session.
- The **service daemon** still verifies the resulting one-use transport capability before
  connecting to its local loopback target.

Grant scope is delegated at enrollment instead of inferred from possession of any machine
credential. The dashboard must explicitly include it when minting the registration ticket.
Revoking the resulting machine credential removes grant sessions issued by it.

## Signed handoff

The requester runs:

```sh
devsite --json access request postgres \
  --request /private/request.json \
  --key /private/requester.key
```

The server separately requires schema version 1. The request signature covers a domain
separator, request id, service keyword, requester endpoint id, and expiry. The command
creates new files rather than overwriting paths and keeps both private by default. Only the
request JSON crosses the sandbox boundary.

The granting party first resolves and plans:

```sh
devsite --json access resolve postgres
devsite --json access grant --request /inbox/request.json --plan
```

Resolution searches only owned services and accepted service shares visible to the granting
account.
An exact unique name is selected automatically. Ambiguous matches require an explicit
`--resource res_…`. The plan verifies the requester signature and reports the exact
resource, owner, requester endpoint, request id, and expiry without issuing a grant.

After user or policy approval, the granting party applies the same intent:

```sh
devsite --json access grant --request /inbox/request.json \
  --approved-plan dsp_…
```

The granting machine's persistent `devsite-endpoint.key` signs the request id, selected
resource, requester endpoint, and grant expiry. The server also verifies that the signed request's
keyword still resolves to that resource. It rejects expired requests, grants longer than 15
minutes, duplicate request ids, credentials without grant scope, and resources outside the
granting account's current access. The `dsp_…` token is signed by the control plane over the
granting credential, request id and keyword, resource, endpoint, request expiry, and grant
expiry. Apply requires it, preventing a request file or selected target from being swapped
after approval.

The granting party returns only `result.grant` and `result.server`. The requester then runs:

```sh
devsite --server SERVER --json access connect GRANT \
  --key /private/requester.key
```

The connector recreates the requested endpoint from that private key, validates that the
grant is delegated and bound to the same endpoint, and emits resident NDJSON lifecycle
events. It refuses non-loopback listeners.

## Expiry and revocation

Requests expire within 10 minutes and request ids are single-use at issuance. Grant
sessions expire within 15 minutes and may mint one capability per TCP connection during
that window. A granting credential has a bounded number of simultaneous active grant
sessions. Credential revocation deletes those sessions and prevents further capabilities
from being minted. A one-use transport capability already minted immediately before
revocation remains limited by its own short expiry and nonce.

## Harness-neutral integration

The canonical interface is the CLI JSON contract and the portable
[`devsite-cli` skill](../skills/devsite-cli/SKILL.md). A harness can execute those commands
directly, expose them through its own tool API, or use the bundled local MCP adapter.

The adapter follows MCP `2026-07-28`:

- clients use `server/discover`, not `initialize`;
- every request carries
  `_meta.io.modelcontextprotocol/protocolVersion` and
  `_meta.io.modelcontextprotocol/clientCapabilities`;
- each response is complete and self-describing; and
- the adapter stores no negotiated client, authorization, initialization, or call-order
  state.

The long-lived stdio process is only a transport. Killing and restarting it does not lose a
logical session because there is no logical session to lose. The MCP plugin manifest is a
convenience package for clients that understand that format, not a requirement on the model
or harness.

See the current official MCP [discovery](https://modelcontextprotocol.io/specification/draft/server/discover),
[tools](https://modelcontextprotocol.io/specification/draft/server/tools), and
[stdio transport](https://modelcontextprotocol.io/specification/draft/basic/transports/stdio)
specifications.
