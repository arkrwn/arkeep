# Sample integrations

Worked, **proven-to-run** examples of consuming arkeep from a service.
Every code sample on this page set is the same source the automated
smoke test actually executes — see
[`scripts/sdk-smoke.sh`](../../scripts/sdk-smoke.sh), which CI's
`sdk-smoke` job runs on every push and pull request (`ubuntu-latest` runs
it against the real `arkeepd`/`arkeep` binaries end to end; `macos-latest`
runs it against `arkeepd/examples/dev-daemon.rs`, an in-memory daemon, for
the reason documented in that script's header and in
[`docs/PROGRESS.md`](../PROGRESS.md)'s "Known gaps" section).

| Page | Covers |
|---|---|
| [`cli.md`](cli.md) | Shell/CLI: setup, systemd unit for a consumer, get/set/rm/list, recovery, audit |
| [`rust.md`](rust.md) | `arkeep-sdk` (Rust), `sdk/rust/arkeep-sdk/` |
| [`go.md`](go.md) | `arkeep-sdk` (Go), `sdk/go/arkeep/` |
| [`python.md`](python.md) | `arkeep-sdk` (Python), `sdk/python/arkeep_sdk/` |
| [`typescript.md`](typescript.md) | `arkeep-sdk` (TypeScript), `sdk/javascript/arkeep-sdk/` |
| [`javascript.md`](javascript.md) | Same package, compiled `dist/` output, from plain JavaScript |
| [`roadmap.md`](roadmap.md) | Planned SDKs: C, C++, Perl, Ruby, and others |
