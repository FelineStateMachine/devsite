dev.site v0.6.1 makes relay selection part of the control-plane configuration.

## Highlights

- The control plane uses the n0 relay preset by default.
- `IROH_SERVICES_API_SECRET` adds endpoint-scoped relay tokens.
- `DEVSITE_RELAY_URLS` selects a comma-separated custom relay list.
- The control plane sends the relay list and scoped token to each endpoint.
- The dev.site deployment keeps its custom relay list in `fly.toml`.

## Upgrade notes

- Database migrations are not required.
- Existing endpoint identities continue to work.
- Self-hosted deployments can remove `DEVSITE_RELAY_URLS` to use the n0 preset.
- Self-hosted deployments can replace `DEVSITE_RELAY_URLS` with their Iroh Services relays.

Homebrew users can upgrade with:

    brew update && brew upgrade FelineStateMachine/tap/devsite
