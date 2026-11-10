# Securing the root (master) private key

`cofferak init --root` prints the root X25519 private key to stdout
**exactly once** and never writes it to disk itself. Everything in this
vault's security model (`docs/SPEC.md` §1) rests on what happens to
that printed value in the seconds after it appears. This page is about
that, specifically — not the per-host unseal keys or service tokens
(those are machine-sealed automatically by `HostSeal`/ADR 0002 and need
no manual handling).

## What the root key actually protects

It's the one thing that can recover this vault if **every** enrolled
host is lost (`cofferak recover --root-key`, `docs/recovery-runbook.md`).
It is not needed for, and should never be used for, day-to-day
operation — `init --host`/`enroll-host`/`enroll-service` never touch it.
If you find yourself reaching for the root key more than once in a
vault's lifetime (initial bootstrap, then maybe one disaster recovery,
ever), something upstream of this key went wrong — treat a second use
as a signal to review what happened.

## Do this

1. **Capture it the moment it's printed, then clear the terminal.**
   Copy it to the offline medium you've already decided on (below)
   before doing anything else in that terminal session. Then
   `clear`/close the terminal and check your shell history doesn't
   retain it (most shells don't echo program *output* into history, but
   verify for yours).
2. **Store it offline, on a medium with no network interface.** In
   order of preference for most setups:
   - A hardware security token/smartcard that can hold an opaque secret
     (e.g. a YubiKey's encrypted storage slot, or a dedicated offline
     hardware wallet-style device). Best option: the key material is
     never in plaintext on any general-purpose filesystem again.
   - An encrypted USB drive (e.g. LUKS/FileVault-encrypted volume) kept
     physically secured (a safe, a locked drawer with controlled
     access), with the key written as one unlabeled text file.
   - A paper or metal backup (printed or hand-transcribed hex), stored
     like you would a legal document or a hardware wallet seed phrase —
     a safe or safety-deposit box, not a desk drawer.
3. **Verify the backup before you consider the key "stored."** Read it
   back from the offline medium and compare against what was printed
   (or, better, run it through `cofferak recover --root-key` in a throwaway
   test vault to confirm it actually unwraps — see
   `docs/recovery-runbook.md`). A backup you haven't verified is a hope,
   not a backup.
4. **Decide who else needs it, in writing, before you need them to have
   it.** A single-person project can stop at step 3. A team should
   decide now — not during an actual disaster — who is authorized to
   hold a copy and what justifies using it, and should prefer splitting
   custody (below) over simply handing a second person the whole key.
5. **Treat it like you'd treat an SSH CA root key or a code-signing
   root cert**, because structurally it is one: compromise of this key
   plus access to a copy of `vault.cofferak` is a total compromise of every
   secret ever stored in this vault (`docs/SPEC.md` §1's threat model is
   explicit that root-key disclosure is outside what the design
   protects against).

## Splitting custody (optional, for teams)

If no single person should be able to recover the vault alone, split
the raw key with an external secret-sharing tool *before* it goes to
offline storage — e.g. Shamir's Secret Sharing via `ssss` (`ssss-split`/
`ssss-combine`, widely available on Linux/macOS package managers) with
a threshold like 3-of-5 custodians. cofferak does not implement secret
sharing itself (ADR 0001 deliberately rejected building this in — see
that ADR for why), so this is an operational practice layered on top:
split the key, distribute shares to separate custodians/locations,
destroy the unsplit copy once shares are distributed and verified.

## Never do this

- **Never put it in a password manager that syncs to the cloud**,
  even "zero-knowledge" ones, unless you've independently verified that
  product's encryption model meets your threat model — this defeats
  the entire point of "never retained on any host running the daemon."
- **Never send it over chat, email, or a ticketing system**, even
  "temporarily" or "just to this one trusted person." Those systems log
  and retain content in ways you don't control.
- **Never commit it to a repository**, including a private one,
  including as an encrypted file whose decryption key is itself
  committed nearby.
- **Never store it on the same host, or the same physical medium, as a
  `vault.cofferak` file or a host's sealed unseal key.** Co-location defeats
  the dual-wrap design (ADR 0001) that's supposed to make a host
  compromise and a root-key compromise independent events.
- **Never type it into a form, script, or AI assistant** (including
  this one) to "double check" it or "help format" it. If you need to
  verify it, use `cofferak recover --root-key` against a disposable test
  vault, locally, offline.

## Rotation

The root key itself has no `cofferak` CLI rotation path today (`rotate-dek`
rotates the DEK, not the root keypair — see `docs/SPEC.md` §7) — this is
a deliberate current limitation, not an oversight; if you need to
rotate the root keypair itself (e.g. after a suspected exposure), that
requires `cofferak init --root` into a fresh vault and re-enrolling every
host/service, tracked as a gap in `docs/PROGRESS.md` if it isn't
already. Rotating the *DEK* (`rotate-dek --hosts <csv>`) does not help
if the root key itself is what's suspected compromised — the root
public key stored in `vault.cofferak` doesn't change, so a leaked root
private key remains valid for that vault until a full re-bootstrap.

## Periodic drills

Run `cofferak recover --root-key` against a copy of a real (or disposable
test) vault on a schedule — quarterly is a reasonable default for most
teams — to confirm the stored key still works and whoever is supposed to
be able to execute recovery actually can, before an actual disaster
forces you to find out live. `docs/recovery-runbook.md` is written for
exactly this: hand it to the person who'd run the drill, unmodified.
