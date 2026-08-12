# JSON output

Every command accepts the global `--json` flag before or after its subcommands. Finite
commands write exactly one JSON value to stdout:

```json
{"schema_version":1,"ok":true,"command":"daemon.status","result":{"running":true,"start_hints":[]}}
```

Every record carries `schema_version: 1`; consumers should reject versions they do not
understand rather than guessing at a changed shape.

Failures are JSON on stdout and retain meaningful exit codes: `1` for runtime failures and
`2` for command-line usage errors.

```json
{"schema_version":1,"ok":false,"command":"service.host","error":{"kind":"runtime","message":"…","causes":[],"suggestions":["Run `devsite service host --help` for valid arguments."]}}
```

Help is structured too: `devsite link set --json --help` succeeds with command `help` and
puts the complete command-specific help in `result.text`. Usage and runtime errors include
recovery suggestions suitable for either display or direct agent consumption.

`devsite connect --json` and `devsite daemon run --json` are resident processes. They emit
one JSON value per line so consumers can process lifecycle events as NDJSON. Human logs and
transport warnings remain on stderr and never contaminate JSON stdout.

JSON mode is non-interactive. In particular, `devsite login --json` requires its token as an
argument rather than prompting on stdin.
