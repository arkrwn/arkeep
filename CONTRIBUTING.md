# Contributing to cofferak

Thanks for your interest! cofferak is an open-source, self-hostable secrets
vault. Contributions — bug reports, docs, platform backends, tests — are
welcome. The flow is deliberately lightweight, but there is one mandatory
step: the **CLA (copyright assignment)**.

## 0. CLA first, before your first PR

All contributions are covered by the Copyright Holder's global CLA
(`CLA.md` in the root of this repository).

Why it's required: so the project owner can protect, rebrand, and relicense
the whole codebase without needing to track down every past contributor for
permission (so the project is never stuck because one old contributor can't
be reached).

How to sign (once, covers every contribution to every project of this
owner, including future ones):

1. **Via PR (easiest):** comment on your first PR:

   > I hereby accept this CLA and assign copyright of my Present and
   > Future Contributions to projects of Arie Kurniawan (arkrwn) to
   > Arie Kurniawan (arkrwn), as described in CLA.md.

2. **Via email:** send "I accept the CLA (copyright assignment)" plus your
   GitHub username to <hubungi.aja@gmail.com>.

The PR will be labeled `waiting-cla` by the maintainer until the CLA is on
record. Contributions without a CLA will not be merged.

Contributing on behalf of a company? See section 8 of `CLA.md`.

## 1. Before opening an issue

- Check the issue list first; comment on an existing one if it matches.
- Bug reports: include the version (tag/commit), platform/toolchain, and
  minimal reproducible steps.
- Security issues: **do not** open a public issue. Email
  <hubungi.aja@gmail.com> with subject `SECURITY: cofferak`.

## 2. Pull requests

- One PR = one topic. Keep it small.
- Fork → branch with a clear name (`feat/<thing>`, `fix/<thing>`).
- Follow the style already in the codebase (`cargo fmt`, `cargo clippy`);
  don't bundle an unrelated mass reformat.
- Always include tests for a feature/fix; existing tests must stay green.
- Use conventional commit messages (`feat:`, `fix:`, `docs:`, `chore:`).

## 3. Development

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

- Rust, edition 2021, MSRV pinned in `rust-toolchain.toml`.
- `cofferak-core` has no dependency on process I/O beyond disk reads/writes
  and must stay platform-agnostic; platform-specific code belongs in
  `cofferak-core/src/seal/{linux,macos}.rs`, gated by `cfg(target_os = ...)`.
- No plaintext secret or key material may ever be written to disk outside
  the one documented operator-controlled export path (`cofferak init
  --root`'s one-time private-key print).

## 4. Review

- The maintainer will review; requested changes are technical, not
  personal — argue the point, not the person.
- Squash merge is the default for this project.

## 5. Your rights as a contributor

- Your name stays in the git history and in the changelog, where one
  exists.
- You remain free to reuse your own original code elsewhere, outside this
  project.
- You can step away from the project at any time — merged contributions
  stay in history and continue to operate under the CLA.

Thanks for helping make the code better!
