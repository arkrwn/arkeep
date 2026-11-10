# Sample integrations

Worked, **proven-to-run** examples of consuming mikavt from a service.
Every code sample on this page set is the same source the automated
smoke test actually executes — see
[`scripts/sdk-smoke.sh`](../../scripts/sdk-smoke.sh), which CI's
`sdk-smoke` job runs on every push and pull request (`ubuntu-latest` runs
it against the real `mikavtd`/`mikavt` binaries end to end; `macos-latest`
runs it against `mikavtd/examples/dev-daemon.rs`, an in-memory daemon, for
the reason documented in that script's header and in
[`docs/PROGRESS.md`](../PROGRESS.md)'s "Known gaps" section).

| Page | Covers |
|---|---|
| [`cli.md`](cli.md) | Shell/CLI: setup, systemd unit for a consumer, get/set/rm/list, recovery, audit |
| [`rust.md`](rust.md) | `mikavt-sdk` (Rust), `sdk/rust/mikavt-sdk/` |
| [`go.md`](go.md) | `mikavt-sdk` (Go), `sdk/go/mikavt/` |
| [`python.md`](python.md) | `mikavt-sdk` (Python), `sdk/python/mikavt_sdk/` |
| [`typescript.md`](typescript.md) | `mikavt-sdk` (TypeScript), `sdk/javascript/mikavt-sdk/` |
| [`javascript.md`](javascript.md) | Same package, compiled `dist/` output, from plain JavaScript |
| [`roadmap.md`](roadmap.md) | Planned SDKs: C, C++, Perl, Ruby, and others |
