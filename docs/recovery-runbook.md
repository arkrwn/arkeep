# Disaster recovery runbook

This runbook walks a new operator through recovering a mikavt vault
when every enrolled host's sealed key is gone — the host machine was
destroyed, its disk was wiped, or its `host.seal` file (or
`<data_dir>/hosts/<host-id>.seal`) is lost or corrupted. It uses the one
break-glass path that does not depend on any enrolled host: the **offline
root private key** that was printed to stdout exactly once, when the
vault was created with `mikavt-cli init --root`, and that you (the
operator) were expected to copy somewhere off-machine at that time — a
password manager, a hardware token, a printed page in a safe.

If you don't have that root private key, this runbook cannot help you:
there is no other way to recover an existing vault's data-encryption key
(DEK). Design intentionally has no "forgot my key" path — see
[`docs/superpowers/specs/2026-11-09-mikavt-design.md`](superpowers/specs/2026-11-09-mikavt-design.md)
for why.

If you still have at least one enrolled host with a working `host.seal`,
you don't need this runbook — use `mikavt-cli enroll-host` instead (see
the root [README](../README.md#commands)); it's the normal path for
adding a host and doesn't touch the root key at all.

## What you need before you start

1. **The root private key**, as a 64-character hex string. This is
   exactly what `init --root` printed between the `=== MIKAVT ROOT
   PRIVATE KEY ===` banner lines when the vault was first created. It
   looks like this (example, not a real key):

   ```
   === MIKAVT ROOT PRIVATE KEY — copy this offline now, it will not be shown again ===
   3a1f...   (64 hex characters)
   ======================================================================================
   ```

2. **The vault's data directory**, with `vault.mika` and `meta.json`
   still intact. This runbook does not help if `vault.mika` itself is
   gone or corrupted — that file holds the only copy of the encrypted
   secrets and every wrapped DEK, including the one wrapped for the root
   key. (Back up `vault.mika`/`meta.json` separately from any single
   host's `host.seal` — that's the whole point of the root-key wrap.)

3. **A machine to run the recovery on.** This becomes the new enrolled
   host. It needs:
   - the `mikavt-cli` binary (built from this repository: `cargo build
     --workspace --release`, then use `target/release/mikavt-cli`);
   - on Linux, `systemd-creds` on `PATH`; on macOS, a user Keychain
     session (recovery seals the new host's key the same way `init
     --host`/`enroll-host` do — see the root
     [README](../README.md#why));
   - a decision for the new host's id — any string not already used by
     an enrolled host in this vault (check with `mikavt-cli audit tail`
     or by inspecting `meta.json`'s host list if unsure).

## Step 1 — turn the hex key back into a 32-byte key file

`recover` reads the root key as **32 raw bytes**, not as hex text. The
value `init --root` printed is the hex *encoding* of those 32 bytes, so
you must decode it before use — writing the hex characters straight into
a file will not work (it's the wrong length and `recover` will reject it
with "root key file is not a valid 32-byte key").

On macOS or Linux, with the hex string in `$ROOT_KEY_HEX`:

```bash
ROOT_KEY_HEX=3a1f...   # paste the 64 hex characters you copied offline
echo -n "$ROOT_KEY_HEX" | xxd -r -p > /tmp/mikavt-root.key
```

Confirm the file is exactly 32 bytes:

```bash
wc -c /tmp/mikavt-root.key   # must print "32"
```

If `xxd` isn't available, `python3` works too:

```bash
python3 -c "import sys; sys.stdout.buffer.write(bytes.fromhex('$ROOT_KEY_HEX'))" > /tmp/mikavt-root.key
```

Treat this file as sensitive for as long as it exists: it unwraps the
vault's DEK directly. Put it somewhere not backed up or synced
(`/tmp` is fine for the duration of this procedure), and delete it in
Step 4 regardless of outcome.

## Step 2 — run `recover`

```bash
mikavt-cli recover \
  --root-key /tmp/mikavt-root.key \
  --new-host <new-host-id> \
  --data-dir <path-to-vault-data-dir>
```

- `--root-key <PATH>` — the 32-byte key file from Step 1.
- `--new-host <ID>` — the id to give this newly-recovered host. Pick
  something that isn't already enrolled (see Prerequisites above);
  `recover` will refuse with "this host is already enrolled" if it is.
- `--data-dir <DIR>` — the vault's data directory (containing
  `vault.mika`). If omitted, it falls back to `$MIKAVT_DATA_DIR`, then
  the platform default (`/var/lib/mikavt` on Linux,
  `~/Library/Application Support/mikavt` on macOS).

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
- wrapped the DEK for `<new-host-id>` and written `vault.mika` +
  `meta.json` back to disk.

You can now start `mikavtd` on this machine against the same
`--data-dir` (or `$MIKAVT_DATA_DIR`) and it will unseal
`<new-host-id>`'s key and serve requests normally — see
[`docs/deployment.md`](deployment.md).

### If it fails instead

| Message | Meaning | What to do |
|---|---|---|
| `root key file is not a valid 32-byte key, or does not match this vault's root public key` | Either the file isn't exactly 32 raw bytes (see Step 1), or it decoded fine but is the wrong keypair for this `vault.mika` (e.g. you pasted the wrong hex string, or you're pointed at a different vault's data directory than the one this key belongs to). | Re-check the file size (`wc -c`), re-copy the hex string carefully, and confirm `--data-dir` points at the vault this root key was generated for. |
| `this host is already enrolled` | `<new-host-id>` is already present in `vault.hosts`. | Pick a different `--new-host` id, or use `enroll-host` instead if you actually meant to work from an existing host. |
| `no vault found in this data directory; run \`init --root\` first` | Either `vault.mika` is missing at `--data-dir`, or (same message, different cause) the vault exists but has never had a DEK generated (no host was ever enrolled — nothing to recover). | Double check `--data-dir`. If `vault.mika` is genuinely gone, there is no vault left to recover — this message is not something `recover` can fix. |

**Safety guarantee:** on any failure above, `recover` makes no changes
to `vault.mika` or to the filesystem — every check runs before any
write, and the one write is an atomic rename, never an in-place
modification. It's safe to fix the problem (per the table) and run the
exact same command again.

## Step 3 — re-establish normal operation

Once the new host is recovered:

1. Start (or restart) `mikavtd` on this machine, pointed at the same
   `--data-dir`. See [`docs/deployment.md`](deployment.md) for running it
   as a systemd service (Linux) or launchd agent (macOS) rather than in
   the foreground.
2. Existing service tokens still work unchanged — `recover` only adds a
   host, it doesn't touch `vault.services` or any stored secret.
3. If you have other machines that also need to be enrolled hosts (for
   redundancy), use `mikavt-cli enroll-host <id> --this-host
   <new-host-id>` from one of them, now that `<new-host-id>` is a valid,
   working enrolled host whose sealed blob can be unsealed.
4. Consider rotating the DEK afterward (`mikavt-cli rotate-dek --hosts
   <csv>`) if the loss of the old host(s) is at all suspicious (e.g.
   stolen hardware, not just failed hardware) — the old host's sealed
   blob being gone doesn't by itself prove the key material was exposed,
   but rotation is cheap insurance and invalidates any copy of the old
   DEK wrap that might have leaked with the lost host.

## Step 4 — clean up the key file, always

Whether Step 2 succeeded or failed, delete the raw key file you created
in Step 1 as soon as you're done with it:

```bash
rm -f /tmp/mikavt-root.key
```

The root private key itself (the hex string) is not single-use — keep it
in the same offline location it came from for any future recovery. Only
the temporary raw-bytes file on this machine's disk needs to go.
