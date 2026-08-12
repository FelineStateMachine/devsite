dev.site puts links and private TCP services on one developer profile. Services stay on
the machines that own them, and approved users connect through capability-gated,
end-to-end encrypted Iroh QUIC. The dev.site control plane never carries service bytes.

## install

macOS users should install with Homebrew:

```sh
brew install FelineStateMachine/tap/devsite
```

Linux and Windows users can download the matching archive below. The Apple Silicon archive
is also provided for direct installation.

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

Sign in at [dev.site](https://dev.site), create a machine credential on the dashboard,
then run:

```sh
devsite login dsm_...
devsite service host 5432 --name postgres
devsite daemon run
```

An approved user can open the service on dev.site, get a one-use ticket, and connect with:

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
