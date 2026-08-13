dev.site v0.6.0 gives static profile pages a small server-rendered update path.

## Highlights

- The control plane renders profile HTML for each viewer.
- Fixi starts profile requests and handles incoming share actions.
- SSEXi receives the initial profile and later profile changes.
- Paxi morphs each profile fragment while the page keeps local folder state.
- Strict TypeScript and Biome now check the browser code.
- The control plane filters profile updates by affected account.

## Identity file change

Version 0.6.0 removes the legacy identity file migration promised in version 0.5.1.

The CLI and daemon use `devsite-endpoint.key` and `devsite-endpoint.pub`. They do not read
or move `identity.key` or `identity.pub`.

If these legacy files remain, start version 0.5.1 once before you install version 0.6.0.

## Upgrade notes

- Database migrations are not required.
- Existing profiles and themes continue to work.
- Existing `devsite-endpoint.key` and `devsite-endpoint.pub` files continue to work.
- The release workflow now checks Rust, TypeScript, Biome, and browser tests.

Homebrew users can upgrade with:

    brew update && brew upgrade FelineStateMachine/tap/devsite
