---
name: devsite-cli
description: Operate and explain the devsite command-line interface. Use when a user asks to publish or change a dev.site profile link, share or stop sharing a local TCP service, connect to a service shared with them, request or grant delegated endpoint-bound service access, inspect hosted resources, check devsite setup, manage the foreground daemon, customize profile presentation, or troubleshoot devsite CLI behavior. Also use for intent such as “share localhost,” “expose my local database,” “request database access,” “publish my docs,” or “what can dev.site do?”
---

# devsite CLI

Use the installed CLI as the source of truth. This skill is portable: use any shell/process and JSON parser available in the current harness; do not require vendor-specific tools, paths, metadata, or callbacks.

## JSON contract

- Prefer `devsite --json …` for automation. A finite command writes exactly one JSON object to stdout; check `schema_version`, then `ok` before using `result`.
- On failure, read `error.message`, `error.causes`, and `error.suggestions`; present or follow the relevant recovery action instead of guessing.
- Inspect command syntax with `devsite <command> --json --help` whenever arguments or available subcommands are uncertain. Structured help succeeds with `command: "help"` and `result.text`.
- Treat stdout as the machine-readable channel. Do not attempt to parse human diagnostics from stderr as JSON.
- JSON mode is non-interactive. Supply values such as an enrollment or connection ticket only when the user provides them; do not echo tickets, machine credentials, or endpoint private keys in reports.
- Treat an issued `dss_…` grant as a short-lived secret. Never put a requester key, machine credential, connection ticket, or issued grant in logs, chat summaries, or files shared with another actor.

## Begin with state

- Use `devsite --json status` for local configuration, enrolled server, endpoint public identity, daemon liveness, and locally configured services. It is a local check.
- Use `devsite --json resources list` to inventory owned remote links/services together with local hosting state and share status. Use it before updating or removing an ambiguously named resource, and to reconcile local and remote state.
- Use `devsite --json doctor` when setup, authentication, daemon registration, compatibility, identity files, or resource drift may be wrong. `result.healthy` is the health outcome; an otherwise successful doctor invocation may legitimately report warnings or failures. Prioritize `result.actions` by `priority`; treat an action with `requires_user_input: true` as a request for missing user authority or material.

## Plan before changing access or deleting

Use `--plan` before every upsert or removal. `--dry-run` is an alias. A plan validates the intended change without writing local configuration, changing the daemon, or mutating the control plane.

```sh
devsite --json link set --name docs --url https://example.com/docs --public --plan
devsite --json service host 5432 --name postgres --share @alice --plan
devsite --json link remove docs --plan
devsite --json service remove postgres --plan
```

- Explain the planned target, visibility, recipients, destination/folder, and effects before applying it. Pay particular attention to effects that revoke access, withdraw invitations, make something public, or require a recipient to re-approve a changed link destination.
- Require a clear target for removals. Obtain confirmation before deleting or materially broadening/narrowing access unless the user's request already explicitly confirms that exact action.
- Apply the same command without `--plan` only after the plan is understood and authorized. A plan is not a transaction; refresh or re-plan if the state may have changed before apply.

## Map user intent to workflows

| Intent | Safe workflow |
| --- | --- |
| Publish a profile link | Plan `link set --name NAME --url HTTPS_URL`; use `--public` for public access, `--share @HANDLE` for invitation-based sharing, or neither for private. Apply after review. |
| Host a local TCP service | Plan `service host PORT --name NAME`; a service always targets loopback on the host. Add repeatable `--share @HANDLE` only when sharing is intended. Apply, then ensure the daemon is running. |
| Stop serving a service | Inspect `resources list`, plan `service remove NAME`, explain remote-access and local-mapping effects, then apply after confirmation. |
| Remove a link | Inspect `resources list`, plan `link remove NAME`, explain access/profile effects, then apply after confirmation. |
| Reach a shared service | Obtain a user-provided, short-lived single-use connection ticket from the approved profile entry. Run `connect TICKET` and wait for its ready event; use `--listen 127.0.0.1:PORT` only for a deliberate loopback port. |
| Request sandboxed access | Create a signed request and separate endpoint key with `access request`; send only the request JSON to an authorised granting party. Keep the key in the requester sandbox and use it with `access connect` after receiving the grant. |
| Grant delegated service access | Resolve the signed keyword, plan the exact endpoint-bound grant, obtain the required policy or user approval, then issue it with a machine credential enrolled for `service_grants:issue`. Return only the grant and its server to the requester. |
| Enroll this machine | Obtain a user-provided single-use machine ticket and run `login TICKET`. This creates or uses the local endpoint identity and stores a revocable machine credential. |
| Diagnose availability | Run `doctor`; use its checks and proposed actions. For a configured but stopped host, start `daemon run` under the harness’s normal long-running-process supervision. |
| Change profile presentation | Discover exact syntax with `theme --json --help`; use `theme properties` before producing a theme declaration file, then `theme set FILE` or `theme clear` as authorized. |

Folders are display grouping, not authorization boundaries. A public profile entry is public; shared entries require the invitee to accept the share. The control plane manages identity and permissions, while service traffic is a peer-to-peer TCP connection to the owner’s local loopback target.

## Delegated endpoint-bound access

Use this workflow when a sandboxed or untrusted worker needs temporary access. Do not give it the granting party machine's identity or credential.

Requester:

```sh
devsite --json access request postgres \
  --request /private/request.json \
  --key /private/requester.key
```

- Create both paths in a requester-private directory. The command refuses existing files and writes them with private permissions.
- Send only `request.json` to the granting party. Its signature binds the service keyword, requester endpoint, request id, and expiry. Never send `requester.key`.
- A request expires within 10 minutes. Issuance consumes its request id once, so retry by creating a new request rather than weakening replay checks.

Granting party:

```sh
devsite --json access resolve postgres
devsite --json access grant --request /inbox/request.json --plan
devsite --json access grant --request /inbox/request.json \
  --approved-plan dsp_…
```

- Granting party commands require a machine credential with the `service_grants:issue` scope. A login alone does not give that credential authority to grant access.
- Resolution is limited to services the granting party account owns or has an accepted share for. If multiple services match, present the candidates and pass the approved `--resource res_…`; never choose an ambiguous fuzzy match silently.
- Always plan first. Show the signed request identity, exact service/resource, owner, requester endpoint, and expiry to the user or policy engine that controls issuance. Apply only with that plan's server-signed `approved_plan` token. It pins these fields so a replaced request file or changed target is rejected.
- Grants last at most 15 minutes and are bound to the requester endpoint. Give the requester only the `dss_…` grant and `server` from the JSON result. Do not give it the granting party credential, granting party endpoint key, or requester's copied key.

Requester connection:

```sh
devsite --server https://dev.site --json access connect dss_… \
  --key /private/requester.key
```

`access connect` is resident NDJSON like ordinary `connect`. It proves possession of the requester key, verifies the grant is issued by the granting party and bound to that endpoint, then opens only a loopback listener. A granting party credential can be revoked independently. Revocation deletes its unredeemed grant sessions. Any minted one-use transport capability remains limited by its short expiry.

Keep the requester and granting party roles distinct even if one harness can execute both. The skill is a protocol and CLI workflow. Any model, shell runner, policy engine, or MCP client can implement the handoff. Do not depend on a named agent framework, vendor callback, or stateful model session.

## Manage resident commands

`devsite --json connect …` and `devsite --json daemon run` are resident processes. Their stdout is NDJSON: parse one JSON object per line and preserve process lifetime. `connect` is ready on its `listening` event; `daemon run` is ready on its `online` event. Continue to surface later error or `shutdown` events. Do not treat the initial process spawn as success and do not block forever without reporting observed state.

Run the daemon only when hosting services. Running a daemon can register this endpoint as the account’s active daemon, so inspect `doctor` when another machine may already be hosting.

## Explain, do not obscure

For discovery requests, lead with the user’s likely outcome, then offer the smallest relevant workflow. Explain that devsite publishes normal links and hosts private TCP byte streams; it is not an HTTP reverse proxy and it does not expose arbitrary non-loopback targets. Prefer small, reversible steps and always report the resulting resource name/ID, visibility, recipients, local listening address, or next action from JSON.

Never claim that a service is reachable merely because its profile resource exists: hosting requires a running daemon, and connecting requires an accepted share and a valid ticket.
