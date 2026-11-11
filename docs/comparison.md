# cofferak vs. other ways to handle secrets

A fair comparison with the tools people reach for before (or instead
of) cofferak: plain `.env` files, HashiCorp Vault, Infisical, and AWS
Secrets Manager. The honest goal here isn't "cofferak beats everything" —
it's helping you pick the right tool for your situation, including
when that tool isn't cofferak.

## At a glance

| | `.env` files | HashiCorp Vault | Infisical | AWS Secrets Manager | **cofferak** |
|---|---|---|---|---|---|
| Encrypted at rest | ❌ (plaintext file) | ✅ | ✅ | ✅ | ✅ |
| Runs without a separate server to operate | ✅ (it's a file) | ❌ | ❌ (SaaS or self-host a full stack) | ✅ (AWS operates it) | ✅ (one daemon binary) |
| Self-hosted, no cloud account required | ✅ | ✅ | Partial (self-host option exists, SaaS is the default path) | ❌ (AWS-only) | ✅ |
| Per-service least-privilege access tokens | ❌ | ✅ | ✅ | ✅ (IAM) | ✅ |
| Audit log of every access | ❌ | ✅ | ✅ | ✅ (CloudTrail) | ✅ |
| Dependency footprint | None | Large (its own clustering, storage backends, plugins) | Large (API server, DB, queue, web UI) | None (fully managed) | Minimal — one daemon, one on-disk file, your OS's own key storage |
| Network service by default | ❌ | ✅ (always) | ✅ (always) | ✅ (always, AWS's network) | ❌ — local Unix socket by default; network (TLS/mTLS) is opt-in |
| Offline / air-gapped friendly | ✅ | Hard (needs its own HA setup) | Hard (SaaS-first design) | ❌ (needs AWS reachability) | ✅ (root key workflow is explicitly offline-first) |
| Setup complexity | Trivial | High (unseal process, storage backend, policies, HA) | Medium–high (full platform) | Low (if you're already on AWS) | Low (one binary, one init command) |
| Vendor/cloud lock-in | None | None (self-hosted) | Low (open-source core) | High (AWS-specific) | None |

## Why migrate off `.env` files

If you're here, you probably already know why: a `.env` file is
plaintext on disk, gets copy-pasted into chat "just this once," ends up
in a screenshot, or gets committed by accident the one time
`.gitignore` wasn't quite right. It has no access control — anything
that can read the file gets everything in it — and no audit trail. It
works fine for a solo prototype. It is not a credential store.

cofferak's entire design (`docs/SPEC.md` §1) is the direct answer to this:
secrets are encrypted at rest, the key that decrypts them is sealed by
your OS's own secure storage (not a file sitting next to the vault),
and every service gets a scoped token instead of blanket file access.

## cofferak vs. HashiCorp Vault

Vault is the mature, battle-tested answer for large organizations that
need dynamic secrets (databases issuing short-lived credentials on
demand), many auth backends, fine-grained policy-as-code, and a team
dedicated to running it. If that's genuinely you, Vault is the right
answer — it does things cofferak deliberately doesn't attempt (ADR 0003,
ADR 0005's rejected-codegen reasoning, and §9's "deliberately out of
scope" all point the same direction: cofferak stays small on purpose).

What cofferak gives up relative to Vault, honestly: no dynamic/leased
secrets, no plugin ecosystem, no multi-datacenter replication, no
built-in UI. What it gives back: nothing to operate beyond one binary
and one on-disk file, an offline-first root-key model that doesn't need
an unseal ceremony with multiple key-holders in the room, and a setup
measured in minutes instead of a Vault cluster's typical multi-day
rollout.

**Pick cofferak if:** you want "Vault's core promise" (encrypted secrets,
scoped access, audit log) without running a cluster, and you don't need
dynamic secrets or a policy language.
**Pick Vault if:** you need dynamic/leased credentials, many
auth methods, or you're already running it at scale and it's working.

## cofferak vs. Infisical

Infisical is the closer peer in spirit — open-source, developer-focused,
built to be easy to adopt — but it's architected as a platform: an API
server, a database, a web dashboard, typically consumed as SaaS (a
self-hosted mode exists but brings the same multi-component stack with
it). That's a real strength if your team wants a shared web UI for
non-technical stakeholders to manage secrets, project-based
organization, and integrations out of the box.

cofferak has none of that UI/platform layer by design — it's a daemon and
a CLI, meant to be the thing *under* your own tooling, not a product
your whole team logs into. If you want a dashboard, Infisical's is
already built; cofferak doesn't have one and isn't trying to.

**Pick cofferak if:** you want the absolute minimum moving parts — no
database, no web server, no SaaS dependency — and you're comfortable
with a CLI/SDK-first workflow.
**Pick Infisical if:** you want a web dashboard for secret management,
multi-project organization, or you're fine with a SaaS dependency (or
willing to run its full self-hosted stack).

## cofferak vs. AWS Secrets Manager

Secrets Manager is the right default if you're already fully committed
to AWS: zero operational burden (AWS runs it), tight IAM integration,
automatic rotation for RDS/Redshift/DocumentDB credentials, and
CloudTrail audit logging you probably already have wired up. For an
AWS-native shop, fighting that integration to use something else is a
real cost, not a hypothetical one.

The trade-off is lock-in and reach: it only exists inside AWS, costs
scale per-secret and per-API-call, and it's not an option for
on-prem/other-cloud/local-dev workloads or anything that needs to run
somewhere AWS can't reach. cofferak runs anywhere a binary can run — your
laptop, a bare-metal box, any cloud, air-gapped — with no per-secret or
per-call billing.

**Pick cofferak if:** you need something that runs outside AWS (or
across multiple environments) without vendor billing per secret
access, or you want it fully portable to any machine.
**Pick AWS Secrets Manager if:** you're AWS-native already and want
zero-ops, with automatic rotation for AWS-managed databases as a
built-in bonus.

## The short version

cofferak's niche is deliberately narrow: the smallest, most portable,
most dependency-free way to get real encryption-at-rest, least-privilege
access tokens, and an audit log — for a team or project that doesn't
want to operate a platform to get there. If your actual need is dynamic
secrets at scale (Vault), a shared web UI for secret management
(Infisical), or you're fully AWS-native already (Secrets Manager),
those tools solve problems cofferak isn't trying to solve. If your actual
need is "stop putting credentials in `.env` files" without taking on a
platform to do it, that's exactly the gap cofferak fills.
