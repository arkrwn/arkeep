# Disaster recovery runbook

This runbook walks a new operator through recovering a cofferak vault
when every enrolled host's sealed key is gone — the host machine was
destroyed, its disk was wiped, or its `host.seal` file (or
`<data_dir>/hosts/<host-id>.seal`) is lost or corrupted. It uses the one
break-glass path that does not depend on any enrolled host: the **offline
root private key** that was printed to stdout exactly once, when the
vault was created with `cofferak init --root`, and that you (the
operator) were expected to copy to offline storage at that time — see
[`docs/key-security.md`](key-security.md) for how to actually do that
(and what *not* to use, e.g. a cloud-synced password manager).

If you don't have that root private key, this runbook cannot help you:
there is no other way to recover an existing vault's data-encryption key
(DEK). The design intentionally has no "forgot my key" path — see
[`docs/SPEC.md`](SPEC.md) §1 and [ADR 0001](adr/0001-envelope-encryption-dual-wrapped-dek.md)
for why.

If you still have at least one enrolled host with a working `host.seal`,
you don't need this runbook — use `cofferak enroll-host` instead (see
the root [README](../README.md#commands)); it's the normal path for
adding a host and doesn't touch the root key at all.

## What you need before you start

1. **The root private key**: the armored block `init --root` printed
   when the vault was created, saved as a text file. It looks like this
   (shortened; the real block is about 70 lines of base64):

   ```
   -----BEGIN COFFERAK ROOT PRIVATE KEY-----
   AgP1o1wQ...
   ...
   -----END COFFERAK ROOT PRIVATE KEY-----
   ```

   The block holds both halves of the root key (X25519 and ML-KEM-1024,
   ADR 0011) and a checksum, so a truncated or mistyped copy is rejected
   before anything is decrypted.

2. **The vault's data directory**, with `vault.cofferak` and `meta.json`
   still intact. This runbook does not help if `vault.cofferak` itself is
   gone or corrupted — that file holds the only copy of the encrypted
   secrets and every wrapped DEK, including the one wrapped for the root
   key. (Back up `vault.cofferak`/`meta.json` separately from any single
   host's `host.seal` — that's the whole point of the root-key wrap.)

3. **A machine to run the recovery on.** This becomes the new enrolled
   host. It needs:
   - the `cofferak` binary (built from this repository: `cargo build
     --workspace --release`, then use `target/release/cofferak`);
   - on Linux, `systemd-creds` on `PATH`; on macOS, a user Keychain
     session (recovery seals the new host's key the same way `init
     --host`/`enroll-host` do — see the root
     [README](../README.md#why));
   - a decision for the new host's id — any string not already used by
     an enrolled host in this vault (check with `cofferak audit tail`
     or by inspecting `meta.json`'s host list if unsure).

## Step 1 — put the key file on the recovery machine

Copy the saved key file from your offline media to the recovery machine,
for example to `/tmp/cofferak-root.key`. If you only have a printed copy,
type the block back in exactly, including the `-----BEGIN` and `-----END`
lines; line breaks and surrounding text don't matter, and `recover`
checks the built-in checksum before using it.

```bash
chmod 600 /tmp/cofferak-root.key
head -1 /tmp/cofferak-root.key   # -----BEGIN COFFERAK ROOT PRIVATE KEY-----
```

Treat this file as sensitive for as long as it exists: it unwraps the
vault's DEK directly. Put it somewhere not backed up or synced
(`/tmp` is fine for the duration of this procedure), and delete it in
Step 4 regardless of outcome.

## Step 2 — run `recover`

On Linux, run it with `sudo` (sealing the new host key uses
`systemd-creds`' root-only host scope — ADR 0009); it hands the files it
writes back to the data directory's owner.

```bash
cofferak recover \
  --root-key /tmp/cofferak-root.key \
  --new-host <new-host-id> \
  --data-dir <path-to-vault-data-dir>
```

- `--root-key <PATH>` — the key file from Step 1.
- `--new-host <ID>` — the id to give this newly-recovered host. Pick
  something that isn't already enrolled (see Prerequisites above);
  `recover` will refuse with "this host is already enrolled" if it is.
- `--data-dir <DIR>` — the vault's data directory (containing
  `vault.cofferak`). If omitted, it falls back to `$COFFERAK_DATA_DIR`, then
  the platform default (`/var/lib/cofferak` on Linux,
  `~/Library/Application Support/cofferak` on macOS).

On success you'll see:

```
host '<new-host-id>' recovered via offline root key
```

This has:
- unwrapped the vault's existing DEK using the root private key (the
  same DEK every other host and every stored secret already uses — your
  existing secrets are untouched and remain readable);
- generated a brand-new random unseal key for `<new-host-id>` and sealed
  it with this machine's platform backend (`systemd-creds` on Linux,
  Keychain on macOS), writing it to
  `<data_dir>/hosts/<new-host-id>.seal`;
- wrapped the DEK for `<new-host-id>` and written `vault.cofferak` +
  `meta.json` back to disk.

You can now start `cofferakd` on this machine against the same
`--data-dir` (or `$COFFERAK_DATA_DIR`) as host `<new-host-id>` and it will
serve requests normally. On Linux, set `REPLACE_WITH_HOST_ID` in the unit
to `<new-host-id>` so `LoadCredentialEncrypted=` delivers the new key —
see [`docs/deployment.md`](deployment.md).

### If it fails instead

| Message | Meaning | What to do |
|---|---|---|
| `root key file is not a valid cofferak root private key (armored block from \`init --root\`), or does not match this vault's root public key` | Either the file isn't a complete, correctly copied armored block (missing BEGIN/END line, a typo caught by the checksum), or it is a valid key for a different vault. | Re-copy the block carefully from your offline copy, and confirm `--data-dir` points at the vault this root key was generated for. |
| `this host is already enrolled` | `<new-host-id>` is already present in `vault.hosts`. | Pick a different `--new-host` id, or use `enroll-host` instead if you actually meant to work from an existing host. |
| `no vault found in this data directory; run \`init --root\` first` | Either `vault.cofferak` is missing at `--data-dir`, or (same message, different cause) the vault exists but has never had a DEK generated (no host was ever enrolled — nothing to recover). | Double check `--data-dir`. If `vault.cofferak` is genuinely gone, there is no vault left to recover — this message is not something `recover` can fix. |

**Safety guarantee:** on any failure above, `recover` makes no changes
to `vault.cofferak` or to the filesystem — every check runs before any
write, and the one write is an atomic rename, never an in-place
modification. It's safe to fix the problem (per the table) and run the
exact same command again.

## Step 3 — re-establish normal operation

Once the new host is recovered:

1. Start (or restart) `cofferakd` on this machine, pointed at the same
   `--data-dir`. See [`docs/deployment.md`](deployment.md) for running it
   as a systemd service (Linux) or launchd agent (macOS) rather than in
   the foreground.
2. Existing service tokens still work unchanged — `recover` only adds a
   host, it doesn't touch `vault.services` or any stored secret.
3. If you have other machines that also need to be enrolled hosts (for
   redundancy), use `cofferak enroll-host <id> --this-host
   <new-host-id>` from one of them, now that `<new-host-id>` is a valid,
   working enrolled host whose sealed blob can be unsealed.
4. Consider rotating the DEK afterward (`cofferak rotate-dek --hosts
   <csv>`) if the loss of the old host(s) is at all suspicious (e.g.
   stolen hardware, not just failed hardware) — the old host's sealed
   blob being gone doesn't by itself prove the key material was exposed,
   but rotation is cheap insurance and invalidates any copy of the old
   DEK wrap that might have leaked with the lost host. Restart `cofferakd`
   after rotating: until then it refuses writes rather than encrypting
   under the old DEK.

## Step 4 — clean up the key file, always

Whether Step 2 succeeded or failed, delete the raw key file you created
in Step 1 as soon as you're done with it:

```bash
rm -f /tmp/cofferak-root.key
```

The root private key itself is not single-use: keep the original in the
same offline location it came from for any future recovery. Only the
temporary copy on this machine's disk needs to go.
