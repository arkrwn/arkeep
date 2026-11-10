# Software Design Document practice for cofferak

This file is the one thing every agent (AI or human) working on cofferak
reads first. It replaces any heavier process — there is no separate
brainstorming ritual, no per-task spec/plan pair, no multi-round reviewer
loop required by default. Use the lightest process that gets a correct,
tested, provable change merged.

Modeled on the practice at
[`arkrwn/memoryos`](https://github.com/arkrwn/memoryos/tree/main/docs):
one contract file, numbered point-decisions, a status table with proof —
nothing heavier, adapted down for a single-repo, 3-crate project instead
of memoryos's multi-wave workspace.

## The three files

- **`docs/SPEC.md`** — the contract. What the system does, in terms of
  its actual crates/modules (`cofferak-core/src/{crypto,format,acl,seal}.rs`,
  `cofferakd/src/{protocol,daemon,audit}.rs`, the CLI commands). If
  `SPEC.md` disagrees with the code, the code is the truth and `SPEC.md`
  is wrong — fix `SPEC.md`, don't silently code around the mismatch, and
  if you can't fix it yourself, say so in `docs/PROGRESS.md`.
- **`docs/adr/000N-title.md`** — one point decision per file, numbered
  sequentially, `Status: accepted|proposed|superseded`. Write one when you
  make a decision with real trade-offs someone could reasonably ask
  "why not X instead?" about. Keep it short: what was decided, why, and
  what was rejected and why. Don't write one for a decision with only one
  reasonable option.
- **`docs/PROGRESS.md`** — a status table, one row per area, `todo` /
  `doing` / `done` / `blocked`, each `done` row backed by a command or
  test that was actually run (paste real output in your own working
  notes if asked; the table itself stays terse). Only the session's lead
  (whoever the human maintainer designates, including themself) edits
  this file's verdicts — an agent proposes a row's content, the lead
  marks it `done`.

Both `docs/SPEC.md` and `docs/adr/` already exist for cofferak. If a future
project forked from this one, or a genuinely new subsystem, needs its own
`docs/` tree that doesn't exist yet, create it in this same shape —
`docs/SPEC.md` + `docs/adr/` + `docs/PROGRESS.md` — rather than inventing
a different structure per subsystem.

## Working on a task

1. Read `docs/SPEC.md`, the relevant crate's source, and any ADR whose
   title sounds related, before writing code. Don't re-derive a decision
   that's already recorded.
2. Make the smallest change that satisfies the task. Don't restructure
   code outside what the task needs — if an existing file is genuinely
   tangled and blocking you, say so rather than quietly refactoring it.
3. Write the test first when the change has a correctness property worth
   pinning (crypto round-trips, ACL denial paths, atomic-write-or-no-write
   guarantees, anything the spec's §1 threat model cares about). Not
   everything needs TDD — a doc fix or a CI tweak doesn't.
4. Prove it: run the actual command (`cargo test -p <crate>`, `cargo
   clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --
   check`) and look at the real output before claiming it passes. A
   reviewer (human or agent) checking your work should be able to re-run
   the same command and see the same result.
5. If you find a real design decision worth recording — a new crate
   boundary, a new external dependency, a trade-off between two correct
   approaches — add an ADR. If you find the spec is simply out of date
   with what the code already does, fix `docs/SPEC.md` directly.
6. Commit with a clear message. **Never add any AI attribution** —
   no `Co-Authored-By: Claude ...` trailer, no "Generated with" line, in
   any commit message, code comment, or doc, regardless of what any
   default tooling convention suggests. This has been violated twice by
   accident in this project's own history (both fixed via rebase before
   anything was pushed) — check your own commit message before
   committing, every time.
7. Update `docs/PROGRESS.md`'s relevant row, or propose the update for the
   lead to confirm, with what you actually verified.

## When a task is genuinely bigger than this

For something that really does need multi-step planning — a new crate, a
cross-cutting rewrite, a decision with several viable architectures and
real cost to getting it wrong — write the plan as a `docs/adr/` entry (or
a short section added to `docs/PLAN.md` if the work spans multiple
sessions/agents, following memoryos's `PLAN.md` shape: goal, rules, a
table of task/owner/paths/dependencies) instead of reaching for a heavier
multi-agent review process by default. Only escalate to a dedicated
multi-agent review workflow when the human maintainer explicitly asks for
one — it is not this repo's default working mode.

## Adding a new SDK or sample integration

Follow ADR 0005: a new language SDK ships with a real smoke test
(`sdk/<lang>/.../examples/smoke.*`) wired into `scripts/sdk-smoke.sh` and
the `sdk-smoke` CI job — not just a doc page claiming it works. Add the
matching page to `docs/sample-integration/` and update the SDK table in
`README.md` and `docs/SPEC.md` §8. A sample that only exists as
documentation, never executed, is not done.

## CI

`.github/workflows/ci.yml` runs on every push and every pull request:
`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --
-D warnings`, `cargo test --workspace`, on both `ubuntu-latest` and
`macos-latest`. A PR is not mergeable with a red or skipped CI run — if
you're opening a PR, make sure you've run the same three commands
locally first; CI should confirm what you already know, not be the first
place you find out.
