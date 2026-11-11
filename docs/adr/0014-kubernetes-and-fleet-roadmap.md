# ADR 0014: Roadmap for Kubernetes and multi-node deployments

Status: proposed (a plan, not implemented)

## Context

cofferak today is a vault **per machine**: one daemon and one
`vault.cofferak` per host, consumed over a local Unix socket or, in server
mode, over mutual TLS. That fits a single server, VMs, CI runners,
laptops and edge devices, and replacing `.env` files.

It does **not** yet replace HashiCorp Vault (or a cloud secrets manager)
for a Kubernetes cluster. Compared with Vault, cofferak lacks:

1. **Shared state across nodes.** Each host has its own vault file;
   writes on one node don't reach another (peer transfers, ADR 0013, are
   explicit and manual).
2. **Workload authentication.** Pods have no way to prove their identity
   other than holding a static service token.
3. **Delivery into pods.** No injector, CSI driver or External Secrets
   integration.
4. **High availability.** One daemon per host, no failover.
5. **Dynamic secrets and leases** (e.g. per-pod database credentials that
   expire), **identity-based policies** (OIDC, groups) and a UI.
6. **An independent security audit.** Vault has been audited repeatedly;
   cofferak (v0.1) has not.

Moving a production cluster from Vault to cofferak before these exist
would be less safe, not more. This ADR records the order in which to
close the gaps, keeping cofferak's strengths: small attack surface,
OS-sealed keys, CNSA-grade and post-quantum cryptography, mandatory mTLS.

## Plan

Each phase ships only with its own ADR, tests that prove it in CI, and
updated docs, as every feature so far has.

### Phase 1: central mode for a cluster (single replica)

- Run `cofferakd` as a Kubernetes `StatefulSet` (1 replica) with a
  persistent volume for `vault.cofferak` and server mode enabled.
- Host key delivery without a TPM on the pod: a KMS-sealed or
  Kubernetes-secret-sealed unseal key as an additional `HostSeal`
  backend, documented with its trade-offs.
- Helm chart and kind-based CI test.

### Phase 2: Kubernetes workload authentication

- A pod presents its projected ServiceAccount token; `cofferakd`
  verifies it via the TokenReview API or the cluster's OIDC JWKS (audience
  and expiry checked) and maps `namespace/serviceaccount` to an access
  policy (path prefixes + permission), replacing static tokens for pods.
- Static tokens keep working for non-Kubernetes clients.

### Phase 3: delivery into pods

- A small init container / sidecar (`cofferak run`-style) that fetches
  secrets with the pod's identity and hands them to the app as
  environment variables or files on a tmpfs volume.
- Later: a CSI driver, and a provider for the External Secrets Operator.

### Phase 4: high availability and replication

- Multiple replicas with leader election, writes go through the leader,
  replicated to followers over mTLS, each follower storing secrets under
  its own sealed key (extending the peer-transfer model of ADR 0013 to
  continuous replication).

### Phase 5: dynamic secrets and policy

- Short-lived database credentials (PostgreSQL, MySQL) issued per
  workload with leases and revocation.
- Policies bound to OIDC identities and groups for human access.

### Phase 6: independent audit

- External security review of the cryptography, protocol and
  implementation before positioning cofferak as a Vault replacement for
  clusters.

## Until then

- Use cofferak where it fits today (single hosts, VMs, CI, laptops, edge,
  `.env` replacement).
- For a Kubernetes cluster already on Vault, keep Vault. Use cofferak on
  developer machines and CI, and move individual secret sets between
  environments with `import-env`, bundles or peer transfers
  ([migration.md](../migration.md)).

## Consequences

The project's claims stay honest: README and comparison docs keep saying
cofferak is per-host today, and this roadmap is the reference for what
"cluster-ready" will require.
