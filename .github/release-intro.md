dev.site v0.3.0 hardens machine enrollment and live service authorization while improving
profile organization and installation guidance. Services continue to stay on the machines
that own them; the dev.site control plane never carries service bytes.

## important upgrade note

This release intentionally replaces the v0.2.0 machine-enrollment flow. Existing v0.2.0
machine credentials will no longer authenticate after the control plane is upgraded.

After installing v0.3.0, sign in at [dev.site](https://dev.site), create a new single-use
machine ticket, and enroll the machine again:

```sh
devsite login dmt_...
```

Then restart `devsite daemon run` or its service-manager unit.

## security hardening

- Dashboard-created machine tickets are plaintext, single-use enrollment secrets. On use,
  the server rotates the ticket into a persistent credential stored only as a hash.
- Machine credentials are bound to the enrolling machine's Ed25519 endpoint. Daemon
  registration requires proof of the matching private key, preventing a copied credential
  from redirecting service traffic to another endpoint.
- Revoking a share, credential, or hosted resource now closes affected active streams. The
  daemon also fails closed when its authorization snapshot remains unavailable.
- Authenticated CLI operations use the control-plane origin saved at enrollment instead of
  combining a saved credential with a command-line server override.
- The durable endpoint public key is available as `identity.pub`; private key storage is
  unchanged.

## workflow improvements

- Profiles support declarative folder order and initial open/closed state through bounded
  theme properties.
- Platform-aware installation guidance is now available from both the landing page and the
  signed-in dashboard.
- Service-ticket and native client terminology now matches the current device-to-device
  architecture, with fixes for interactive accordion theme state.

## install

Apple Silicon macOS users can install or upgrade with Homebrew:

```sh
brew install FelineStateMachine/tap/devsite
# Existing installations:
brew update && brew upgrade FelineStateMachine/tap/devsite
```

Linux and Windows users can download the matching archive below.

| archive target | system |
| --- | --- |
| `aarch64-apple-darwin` | Apple Silicon macOS |
| `x86_64-unknown-linux-gnu` | x86-64 Linux |
| `aarch64-unknown-linux-gnu` | ARM64 Linux |
| `x86_64-pc-windows-msvc` | x86-64 Windows |

Each archive contains the `devsite` CLI, README, and Apache-2.0 license. `SHA256SUMS`
contains checksums for every archive.

On Linux, extract the archive and put `devsite` somewhere on `PATH`:

```sh
tar -xzf devsite-*-linux-gnu.tar.gz
sudo install -m 0755 devsite-*-linux-gnu/devsite /usr/local/bin/devsite
```

On Windows, extract the `.zip` and put the directory containing `devsite.exe` on `PATH`.

## first service

```sh
devsite service host 5432 --name postgres
devsite daemon run
```

An approved user can open the service on dev.site, get a one-use connection ticket, and
connect with:

```sh
devsite connect dst_...
```

The daemon is a portable foreground process. Homebrew can supervise it on macOS, systemd
can supervise it on Linux, and any service manager can keep `devsite daemon run` alive.

## verify a download

```sh
sha256sum --check SHA256SUMS
gh attestation verify <archive> --repo FelineStateMachine/devsite
```
