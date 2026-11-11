# ADR 0005: Multi-language SDKs over the shared wire protocol, proven in CI

Status: accepted

arkeep's daemon protocol (`docs/SPEC.md` §6) is a small newline-delimited
JSON format over a Unix socket — simple enough that a thin client in any
language is a translation exercise, not a design problem. Rather than
publish only documentation describing the format and leave every
consumer to reimplement it, this project ships real client SDKs
(`sdk/rust`, `sdk/go`, `sdk/python`, `sdk/javascript`) and commits to a
standing rule: every SDK's claim to work is backed by a smoke test
(`sdk/<lang>/.../examples/smoke.*`) that `scripts/sdk-smoke.sh` runs for
real against a real daemon, wired into CI (`sdk-smoke` job). A
documented-but-untested SDK is worse than no SDK — it invites a consumer
to trust something nobody has run.

Each SDK is intentionally minimal: connect, get, set, rm, list, and the
same error taxonomy (`Denied`/`NotFound`/remote error/protocol error).
No connection pooling, no retry logic, no higher-level secret-caching —
those are legitimate things a consumer can add on top, not something
this project should bake into four codebases before anyone has asked
for them (YAGNI).

Considered and rejected: generating SDKs from a schema (e.g. an OpenAPI/
protobuf-style spec) rather than hand-writing each one. Rejected for now
because the protocol is small enough that codegen tooling and its
maintenance would cost more than four small hand-written clients; worth
revisiting if a fifth or sixth language SDK appears (see
`docs/sample-integration/roadmap.md`).
