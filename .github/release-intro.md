dev.site v0.5.1 moves production Iroh traffic to the managed shared relay tier.

## highlights

- The CLI and daemon use four project relays through an Iroh custom relay map.
- The control plane keeps the Iroh Services API key in its environment.
- The control plane gives each client and daemon an endpoint-scoped relay token.
- Public Iroh relays remain available only to transport integration tests.

## deployment

Set `IROH_SERVICES_API_SECRET` on the control plane before you release the new CLI.
The server must return scoped relay tokens to version 0.5.1 clients.

The relay token grants relay use only. It does not grant access to a dev.site service.
The existing signed capability checks still control each service connection.

## identity file migration

Version 0.5.1 continues to move legacy `identity.key` and `identity.pub` files to
`devsite-endpoint.key` and `devsite-endpoint.pub`.

The migration checks only the dev.site config directory. It moves a legacy file only when
the destination file does not exist.

`devsite doctor` warns that version 0.6.0 removes legacy file support.

Before you upgrade to version 0.6.0, run `devsite login` or `devsite daemon run` with
version 0.5.1 or an earlier version.

## upgrade notes

- Database migrations are not required.
- Existing `devsite-endpoint.key` and `devsite-endpoint.pub` files continue to work.
- Version 0.6.0 will not read or move `identity.key` or `identity.pub`.

Homebrew users can upgrade with:

    brew update && brew upgrade FelineStateMachine/tap/devsite
