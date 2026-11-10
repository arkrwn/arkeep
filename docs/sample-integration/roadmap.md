# SDK roadmap

**Shipped and smoke-tested in CI today:** Rust, Go, Python,
TypeScript/JavaScript (one package) — see the other pages in this
directory.

**Planned, not yet started:**

| Language | Notes |
|---|---|
| C | A thin libmikavt would let every other native-FFI language (Ruby, PHP, Lua, …) bind to one C ABI instead of each reimplementing the wire protocol. Likely the right investment *before* C++/Perl/Ruby below, rather than parallel to them. |
| C++ | A header-only or small static-lib wrapper over the C ABI above, idiomatic RAII `Client`. |
| Perl | Thin bindings over the C ABI (XS) or a pure-Perl socket client mirroring the Python SDK's approach (stdlib-only, no XS, is the simpler initial option). |
| Ruby | Same choice as Perl: FFI over the C ABI, or a pure-Ruby stdlib-only socket client first. |

No committed timeline. Each new SDK should follow the same bar the
existing four do: a real smoke test added to `scripts/sdk-smoke.sh`,
wired into CI, proven against a real daemon — not merely documented.

**Also tracked, not language-specific:** publishing these SDKs to their
respective package registries (crates.io, pkg.go.dev, PyPI, npm) once
the project is ready to commit to API stability for them. Today they are
consumed via local path/relative references (see each language's page
in this directory) — a deliberate choice while the wire protocol and SDK
surface area are still young.
