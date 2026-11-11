# ADR 0003: No external vault/KMS dependency

Status: accepted

arkeep does not call HashiCorp Vault, a cloud KMS, or any other
network-based secret service. It is a standalone, self-contained process
pair (`arkeepd` + `arkeep` CLI) over a local Unix socket, using only the
host OS's own credential-sealing primitive (ADR 0002) and a local
on-disk file (`vault.arkeep`).

This trades the operational features of a managed vault (clustering,
dynamic secrets, multi-region replication) for zero external
dependencies and a minimal trust boundary: anyone who can read this
repo's code can audit everything the vault does, with nothing to
configure or trust beyond the local OS.
