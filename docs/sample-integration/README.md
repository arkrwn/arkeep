# Sample integrations

Worked, **proven-to-run** examples of consuming cofferak from a service.
Every code sample on this page set is the same source the automated
smoke test actually executes — see
[`scripts/sdk-smoke.sh`](../../scripts/sdk-smoke.sh), which CI's
`sdk-smoke` job runs on every push and pull request (`ubuntu-latest` runs
it against the real `cofferakd`/`cofferak` binaries end to end; `macos-latest`
runs it against `cofferakd/examples/dev-daemon.rs`, an in-memory daemon, for
the reason documented in that script's header and in
[`docs/PROGRESS.md`](../PROGRESS.md)'s "Known gaps" section).

| Page | Covers |
|---|---|
| [`cli.md`](cli.md) | Shell/CLI: setup, systemd unit for a consumer, get/set/rm/list, recovery, audit |
| [`rust.md`](rust.md) | `cofferak-sdk` (Rust), `sdk/rust/cofferak-sdk/` |
| [`go.md`](go.md) | `cofferak-sdk` (Go), `sdk/go/cofferak/` |
| [`python.md`](python.md) | `cofferak-sdk` (Python), `sdk/python/cofferak_sdk/` |
| [`typescript.md`](typescript.md) | `cofferak-sdk` (TypeScript), `sdk/javascript/cofferak-sdk/` |
| [`javascript.md`](javascript.md) | Same package, compiled `dist/` output, from plain JavaScript |
| [`roadmap.md`](roadmap.md) | Planned SDKs: C, C++, Perl, Ruby, and others |
