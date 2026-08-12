dev.site v0.5.0 improves the public documentation and homepage guidance for access, tickets,
keys, and service transport.

## highlights

- New concept guides explain tickets, keys and endpoint identities, and the ALPN wire
  protocol.
- The homepage shows the delegated access workflow from request through service connection.
- Command examples use colour to distinguish commands, subcommands, options, values, and
  ticket values.
- Documentation now calls the approving human or automated process the granting party.

## tickets, keys, and protocol

The ticket guide explains each ticket type, its issuer, use count, lifetime, storage, and
revocation rules.

The key guide explains endpoint identity, requester keys, control-plane signing keys, and
private key storage.

The ALPN guide describes `devsite/tcp/1`, its QUIC handshake, frame format, capability
checks, and version boundary.

## identity file migration

Version 0.5.0 continues to move legacy `identity.key` and `identity.pub` files to
`devsite-endpoint.key` and `devsite-endpoint.pub`.

The migration checks only the dev.site config directory. It moves a legacy file only when
the destination file does not exist.

`devsite doctor` now warns that version 0.6.0 removes legacy file support.

Before you upgrade to version 0.6.0, run `devsite login` or `devsite daemon run` with
version 0.5.0 or an earlier version.

## upgrade notes

- Database migrations are not required.
- Existing `devsite-endpoint.key` and `devsite-endpoint.pub` files continue to work.
- Version 0.6.0 will not read or move `identity.key` or `identity.pub`.

Homebrew users can upgrade with:

    brew update && brew upgrade FelineStateMachine/tap/devsite
