# JSON output

Every command accepts the global `--json` flag before or after its subcommands. Finite
commands write exactly one JSON value to stdout:

```json
{"schema_version":1,"ok":true,"command":"daemon.status","result":{"running":true,"start_hints":[]}}
```

Every record carries `schema_version: 1`; consumers should reject versions they do not
understand rather than guessing at a changed shape.

Failures are JSON on stdout and retain meaningful exit codes: `1` for runtime failures and
`2` for command-line usage errors.

```json
{"schema_version":1,"ok":false,"command":"service.host","error":{"kind":"runtime","message":"…","causes":[],"suggestions":["Run `devsite service host --help` for valid arguments."]}}
```

Help is structured too: `devsite link set --json --help` succeeds with command `help` and
puts the complete command-specific help in `result.text`. Usage and runtime errors include
recovery suggestions suitable for either display or direct agent consumption.

`devsite connect --json` and `devsite daemon run --json` are resident processes. They emit
one JSON value per line so consumers can process lifecycle events as NDJSON. Human logs and
transport warnings remain on stderr and never contaminate JSON stdout.

JSON mode is non-interactive. In particular, `devsite login --json` requires its ticket as an
argument rather than prompting on stdin.

## Inventory, plans, and diagnostics

`devsite resources list --json` joins the control plane's owned resources with this
machine's hosted-service config. Service states distinguish `serving_here`,
`configured_here`, and `not_configured_here`; `local_only_services` identifies local
entries whose remote resource is already absent.

Resource mutations accept `--plan` (`--dry-run` is an alias):

```console
devsite link set --name docs --url https://example.com --public --plan --json
devsite service remove postgres --plan --json
```

Plans return `applied: false` with validated field, recipient, effect, and local-config
changes. They never write remote or local state. Applied mutations retain their existing
result fields and add `applied: true` plus the authoritative plan the server applied.

`devsite doctor --json` returns a report rather than treating an unhealthy installation as
a command failure. The envelope remains `ok: true` when the report was produced; inspect
`result.healthy`, `result.checks`, and `result.actions`. Doctor checks endpoint identity,
file permissions, server/API compatibility, the pinned signing key, credential binding,
daemon registration, and remote/local resource drift. It does not open connections to
hosted services.

## Brokered access

`devsite access request SERVICE --request FILE --key FILE --json` creates a public signed
request and a separate private requester endpoint key. Its result contains
`request`, `request_path`, `key_path`, and `handoff: "share_request_only"`. The request
object has schema version, request id, signed service keyword, requester endpoint id, expiry,
and proof. The two paths must differ and must not exist.

`devsite access resolve KEYWORD --json` requires a machine credential enrolled with the
`service_grants:issue` scope. It returns matching accessible services with resource id,
name, optional owner handle, and exact-name-match state.

`devsite access grant --request FILE --plan --json` validates and resolves the signed
request without issuing a grant. If resolution is ambiguous, supply an approved
`--resource res_…`. The plan returns a server-signed `approved_plan` token covering the
exact broker credential, request, resource, endpoint, and expiry. Apply with
`--approved-plan dsp_…`; changed inputs are rejected. A successful apply returns the request
id, resource id, name and owner, requester endpoint id, expiry, short-lived `dss_…` grant,
and `server`. Treat the grant as a secret and return only the grant and server to the
requester.

`devsite access connect GRANT --key FILE --json` is resident NDJSON. It validates that the
grant is broker-issued and bound to the supplied key, then emits the same `listening`,
`connection`, error, and shutdown lifecycle records as ordinary `connect`.
