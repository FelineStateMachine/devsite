# systemd user service

Native Linux packages should install `devsite.service` to the system user-unit directory,
normally `/usr/lib/systemd/user/`. The unit assumes the package installs the binary at
`/usr/bin/devsite`; packages using another prefix should replace `ExecStart` accordingly.

Users enable the daemon for their account after `devsite login`:

```bash
systemctl --user enable --now devsite.service
```

The foreground process remains `devsite daemon run`; the unit only supplies restart and
login-session supervision.
