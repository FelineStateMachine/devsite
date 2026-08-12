dev.site v0.4.0 makes the CLI an agent-ready control surface, adds scoped brokered access
for sandboxed workers, and separates the application identity boundary from its default
OIDC provider.

## highlights

- devsite resources list --json now reconciles remote resources with local hosting state.
- Resource upserts and removals support --plan / --dry-run, and devsite doctor --json
  reports state-aware recovery actions without probing hosted services.
- Endpoint identity files now use the semantic devsite-endpoint.key and
  devsite-endpoint.pub names. Existing files in the devsite configuration directory are
  migrated automatically.
- A portable, model- and harness-neutral CLI skill documents the JSON and resident-process
  contracts. Release archives now include the complete docs, skills, and
  plugins/devsite-access bundles.

## scoped service broker

A sandboxed requester can generate a signed service-keyword request and retain its private
endpoint key. A machine enrolled with the explicit service_grants:issue scope can resolve
that keyword among services its account may access, review a dry-run, and issue a
short-lived grant bound to the requester endpoint.

Grant application requires a server-signed dsp_ approval token over the exact broker
credential, request, resource, endpoint, and expiry. Request ids are single-use, grants
expire within 15 minutes, ambiguous service matches require an explicit resource id, and
revoking the broker credential removes grant sessions it issued.

The optional devsite-access plugin exposes the same workflow through a portable MCP
2026-07-28 stdio adapter. It uses server/discover and per-request protocol metadata, has
no initialize handshake or connection-scoped session state, supports request cancellation,
and prevents its generic CLI tool from bypassing grant planning.

## authentication portability

Shoo remains the default login provider, but the server now treats it as an OIDC adapter
rather than part of the account model. Deployments can configure another public OIDC
provider with explicit issuer, authorization, token, JWKS, client, scope, and algorithm
settings. Accounts are keyed by verified (issuer, subject) identity pairs, and the browser
never receives provider tokens.

## upgrade notes

- Database migrations are automatic.
- Existing CLI and daemon enrollment continues to work. Broker authority is not added to
  existing machine credentials; create a new machine ticket with the service-grant option
  enabled when a machine should act as a broker.
- Deploy the v0.4.0 control plane before using the new access commands.

Homebrew users can upgrade with:

    brew update && brew upgrade FelineStateMachine/tap/devsite
