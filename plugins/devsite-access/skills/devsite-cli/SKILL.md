---
name: devsite-cli
description: Operate and explain the devsite command-line interface. Use for publishing profile links, hosting or connecting to private TCP services, requesting or granting delegated endpoint-bound service access, inspecting resources, checking setup, managing the foreground daemon, or troubleshooting devsite CLI behavior.
---

# devsite CLI

Use the installed CLI as the source of truth. This skill is portable: use any shell/process and JSON parser supplied by the current harness. Do not require a specific model vendor, agent framework, callback, path convention, or stateful model session.

## JSON contract

- Prefer `devsite --json …` for automation. A finite command writes exactly one JSON object to stdout; check `schema_version`, then `ok` before using `result`.
- On failure, use `error.message`, `error.causes`, and `error.suggestions` instead of guessing.
- Inspect syntax with `devsite <command> --json --help`. Structured help returns `command: "help"` and `result.text`.
- JSON mode is non-interactive. Never echo machine credentials, tickets, endpoint keys, or issued `dss_…` grants in logs or summaries.

## Begin with state

- `devsite --json status` reports local configuration, enrollment, endpoint public identity, daemon liveness, and locally configured services.
- `devsite --json resources list` inventories owned remote resources with local hosting and share state. Use it before changing an ambiguous target.
- `devsite --json doctor` diagnoses identity, permissions, authentication, compatibility, daemon registration, and resource drift. Inspect `result.healthy`, then prioritize `result.actions`; an action with `requires_user_input: true` needs user authority.

## Plan mutations

Use `--plan` before upserts, removals, or delegated grant issuance. `--dry-run` is an alias.

```sh
devsite --json link set --name docs --url https://example.com/docs --public --plan
devsite --json service host 5432 --name postgres --share @alice --plan
devsite --json service remove postgres --plan
```

Explain the exact target, visibility, recipients, destination, and effects. Apply the same command without `--plan` only after that exact plan is authorized. Refresh the plan when relevant state may have changed.

## Common workflows

| Intent | Safe workflow |
| --- | --- |
| Publish a link | Plan `link set --name NAME --url HTTPS_URL`; add `--public` or repeatable `--share @HANDLE` only as intended, then apply. |
| Host loopback TCP | Plan `service host PORT --name NAME`; add shares only as intended, apply, then keep `daemon run` alive. |
| Remove a resource | Inspect `resources list`, plan `link remove NAME` or `service remove NAME`, explain effects, then apply. |
| Connect normally | Use the approved, short-lived single-use ticket with `connect TICKET`; choose only a loopback `--listen` address. |
| Request sandbox access | Create a signed request and separate endpoint key with `access request`; send only the request JSON to an authorised granting party. |
| Grant delegated sandbox access | Resolve the signed keyword, plan the endpoint-bound grant, obtain policy or user approval, then issue it with a scoped granting party credential. |
| Diagnose | Run `doctor`; if hosting is configured but stopped, supervise `daemon run` as a resident process. |

Folders are presentation, not authorization. Public entries are public; shared entries require acceptance. Services are protocol-neutral TCP byte streams to the owner's loopback target, not HTTP reverse proxies.

## Delegated endpoint-bound access

Requester:

```sh
devsite --json access request postgres \
  --request /private/request.json \
  --key /private/requester.key
```

- Create both paths in a requester-private directory. The command refuses collisions and writes private files.
- Send only `request.json` to the granting party. Never send `requester.key`.
- The signature binds the service keyword, requester endpoint, request id, and expiry. Requests expire within 10 minutes and issuance consumes each request id once.

Granting party:

```sh
devsite --json access resolve postgres
devsite --json access grant --request /inbox/request.json --plan
devsite --json access grant --request /inbox/request.json \
  --approved-plan dsp_…
```

- These commands require a machine credential with the `service_grants:issue` scope. A login alone does not give that credential authority to grant access.
- Resolution contains only services the granting party account owns or has an accepted share for. If several candidates match, present them and pass the authorised `--resource res_…`; never guess an ambiguous match.
- Show the exact service/resource, owner, requester endpoint, request id, and expiry to the user or policy engine. Issue only with that plan's server-signed `approved_plan` token; changed inputs will be rejected.
- Grants last at most 15 minutes and are bound to the requester's endpoint. Return only the JSON result's `grant` and `server`; never return granting party credentials or endpoint keys.

Requester:

```sh
devsite --server https://dev.site --json access connect dss_… \
  --key /private/requester.key
```

`access connect` is resident NDJSON. It proves possession of the requester key, validates the endpoint binding, and opens only a loopback listener. Keep requester and granting party roles distinct even if one harness can execute both.

## Resident commands

`connect`, `access connect`, and `daemon run` emit one JSON lifecycle event per line. Keep the process alive, parse NDJSON, and report readiness only after `listening` or `online`. Continue surfacing later error and shutdown events.

Never claim that a service is reachable solely because its resource exists: the host daemon must be online, the share must be accepted, and the ticket or grant must be valid.
