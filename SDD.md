# Software Design Document practice for cofferak

Read this file first before working on cofferak, whether you are a
person or an agent. It describes the whole process: there is no separate
brainstorming step, no per-task spec/plan pair, and no multi-round review
loop by default. Use the lightest process that gets a correct, tested,
provable change merged.

The practice is modeled on
[`arkrwn/memoryos`](https://github.com/arkrwn/memoryos/tree/main/docs)
(one contract file, numbered point decisions, a status table with proof),
reduced to fit a single repository: a Cargo workspace of four crates
(`cofferak-core`, `cofferakd`, `cofferak-cli`, `sdk/rust/cofferak-sdk`)
plus the Go, Python and TypeScript/JavaScript SDKs under `sdk/`.

## The documents

- **`SDD.md`** (this file): how work is done and documented.
- **[`docs/SPEC.md`](docs/SPEC.md)**: the contract. What the system does,
  in terms of its actual crates and modules
  (`cofferak-core/src/{crypto,format,acl}.rs` and `seal/`,
  `cofferakd/src/{protocol,daemon,audit,tls_server}.rs`, the CLI
  commands). If `SPEC.md` disagrees with the code, the code is the truth
  and `SPEC.md` is wrong: fix `SPEC.md`, don't code around the mismatch,
  and if you can't fix it yourself, say so in `docs/PROGRESS.md`.
- **[`docs/adr/`](docs/adr/README.md)**: architecture decision records,
  one point decision per file, indexed in
  [`docs/adr/README.md`](docs/adr/README.md). See "ADR conventions"
  below.
- **[`docs/PROGRESS.md`](docs/PROGRESS.md)**: a status table, one row per
  area, `todo` / `doing` / `done` / `blocked`, each `done` row backed by a
  command or test that was actually run, plus a "Known gaps / open items"
  list. The table stays terse. Only the session's lead (whoever the
  maintainer designates, including themself) changes a verdict: an agent
  proposes a row's content, the lead marks it `done`.

Operator and user documentation (`README.md`, `docs/deployment.md`,
`docs/key-security.md`, `docs/recovery-runbook.md`,
`docs/sample-integration/`) is kept in step with the code but is not
part of the design record.

A new subsystem or a fork that needs its own design docs uses the same
shape (`SPEC.md` + `adr/` + `PROGRESS.md`) rather than a new structure.

## ADR conventions

- File name `docs/adr/NNNN-short-title.md`, numbered sequentially.
- First line `# ADR NNNN: <title>`, then a `Status:` line, then the
  body under `##` headings, typically Context, Decision, Alternatives
  considered, Proof, Consequences (use the ones that apply).
- Status is `proposed`, `accepted`, `superseded by ADR NNNN`, or
  `accepted, amended by ADR NNNN` when a later ADR replaces part of it.
- ADRs are history. When a later decision changes an earlier one, write
  a new ADR and add a short `> Amended by ADR NNNN: ...` note under the
  older ADR's Status line; don't rewrite the older decision or its
  reasoning.
- Write one when a decision has real trade-offs someone could ask "why
  not X instead?" about. Keep it short: what was decided, why, what was
  rejected and why. Skip it when there was only one reasonable option.
- Add a row to `docs/adr/README.md` for every new ADR, and update the
  status column when one is amended or superseded.

## Working on a task

1. Read `docs/SPEC.md`, the relevant crate's source, and any related ADR
   before writing code. Don't re-derive a decision that's already
   recorded.
2. Make the smallest change that satisfies the task. If an existing file
   is tangled and blocking you, say so rather than quietly refactoring
   it.
3. Write the test first when the change has a correctness property worth
   pinning (crypto round trips, ACL denial paths, atomic-write-or-no-write
   guarantees, anything in the spec's threat model). A doc fix or a CI
   tweak doesn't need one.
4. Prove it: run the actual commands (`cargo test -p <crate>`,
   `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo fmt --all -- --check`) and read the output before claiming it
   passes. A reviewer should be able to re-run the same commands and see
   the same result.
5. Record a real design decision (a new crate boundary, a new external
   dependency, a trade-off between two correct approaches) as an ADR. If
   the spec is simply out of date with the code, fix `docs/SPEC.md`
   directly.
6. Commit with a clear message. **Never add any AI attribution**: no
   `Co-Authored-By` trailer naming an AI tool, no "Generated with" line,
   in any commit message, code comment or doc, whatever a tool's default
   suggests. Check the message before every commit.
7. Update the relevant `docs/PROGRESS.md` row, or propose the update for
   the lead to confirm, with what you actually verified.

## Larger tasks

For work that needs multi-step planning (a new crate, a cross-cutting
rewrite, a decision with several viable designs and a real cost to
getting it wrong), write the plan as an ADR. If the work spans several
sessions or agents, also create `docs/PLAN.md` (it does not exist today)
in memoryos's `PLAN.md` shape: goal, rules, and a table of
task/owner/paths/dependencies. Use a dedicated multi-agent review only
when the maintainer asks for one; it is not this repo's default.

## Adding an SDK or sample integration

Follow ADR 0005: a new language SDK ships with a smoke test
(`sdk/<lang>/.../examples/smoke.*`) wired into `scripts/sdk-smoke.sh`,
and a TLS smoke test (`examples/smoke_tls.*`) wired into
`scripts/server-mode-smoke.sh`, including its rejection cases (ADR 0008,
ADR 0011). Both scripts run in the `sdk-smoke` CI job. Add the matching
page to `docs/sample-integration/` and update the SDK tables in
`README.md` and `docs/SPEC.md`. A sample that exists only as
documentation, never executed, is not done.

## CI and toolchain

`rust-toolchain.toml` pins Rust 1.98.1, which CI installs. The workspace
MSRV (`rust-version` in `Cargo.toml`) is 1.89.

`.github/workflows/ci.yml` runs on every push and pull request, on
`ubuntu-latest` and `macos-latest`:

- `test` job: `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, and on Linux the `seal_linux` test re-run as
  root (it fails if the test skips).
- `sdk-smoke` job: `scripts/quickstart-check.sh` (the README Quickstart
  run as written), `scripts/sdk-smoke.sh` (full mode on both Linux and
  macOS), `scripts/server-mode-smoke.sh`, and `scripts/bench.sh`
  (informational).

A PR is not mergeable with a red or skipped CI run. Run the fmt, clippy
and test commands locally first; CI should confirm what you already
know.
