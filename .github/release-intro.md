dev.site v0.3.1 is a small presentation and CLI-feedback patch for
[v0.3.0](https://github.com/FelineStateMachine/devsite/releases/tag/v0.3.0).

## changes

- Successful CLI/server version validation now appears as a green check during login;
  incompatible clients fail before consuming the enrollment ticket.
- The public connection diagram now shows endpoint proof and registration plus the daemon's
  live authorization-snapshot sync.

There are no additional protocol, database, or enrollment changes in this patch. See the
[v0.3.0 release](https://github.com/FelineStateMachine/devsite/releases/tag/v0.3.0) for
installation instructions, the security-hardening summary, and its required re-enrollment
step.

Homebrew users can upgrade with:

```sh
brew update && brew upgrade FelineStateMachine/tap/devsite
```
