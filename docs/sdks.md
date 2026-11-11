# SDKs

A consuming service talks to `cofferakd` over its Unix socket - or, in
[server mode](server-mode.md), TLS/mTLS over TCP - using the
newline-delimited JSON protocol in [`docs/SPEC.md`](SPEC.md) §6.
Four client SDKs implement it today, **all four over both transports**
 - each is smoke-tested for real against a running daemon in CI
(`scripts/sdk-smoke.sh` for the Unix socket, `scripts/server-mode-smoke.sh`
for TLS/mTLS including adversarial reject cases, both wired into
`.github/workflows/ci.yml`), not just documented:

| Language | Package | TLS library | Example |
|---|---|---|---|
| Rust | [`sdk/rust/cofferak-sdk`](https://github.com/arkrwn/cofferak/blob/main/sdk/rust/cofferak-sdk) | `rustls` | [`docs/sample-integration/rust.md`](sample-integration/rust.md) |
| Go | [`sdk/go/cofferak`](https://github.com/arkrwn/cofferak/blob/main/sdk/go/cofferak) | `crypto/tls` (stdlib) | [`docs/sample-integration/go.md`](sample-integration/go.md) |
| Python | [`sdk/python/cofferak_sdk`](https://github.com/arkrwn/cofferak/blob/main/sdk/python/cofferak_sdk) | `ssl` (stdlib) | [`docs/sample-integration/python.md`](sample-integration/python.md) |
| TypeScript | [`sdk/javascript/cofferak-sdk`](https://github.com/arkrwn/cofferak/blob/main/sdk/javascript/cofferak-sdk) | `node:tls` (stdlib) | [`docs/sample-integration/typescript.md`](sample-integration/typescript.md) |
| JavaScript | same package, compiled `dist/` | `node:tls` (stdlib) | [`docs/sample-integration/javascript.md`](sample-integration/javascript.md) |

The Go, Python and Node SDKs use only their language's standard library;
the Rust SDK uses `rustls` on AWS-LC, the same stack as the daemon.
Copy-paste samples for all four, verified against a running daemon, are
in [docs/getting-started.md](getting-started.md#6-read-secrets-from-code-sdks).

```python
# Python, the shortest example - same shape in every SDK above.
from cofferak_sdk import Client

client = Client("/run/cofferak/cofferakd.sock")
client.set("<token>", "myapp/DB_PASSWORD", b"s3cr3t")
value = client.get("<token>", "myapp/DB_PASSWORD")
```

None of these are published to a package registry yet - consume them via
a local path/relative reference (see each SDK's own page above) until
the wire protocol and SDK surface area are stable enough to commit to.
Planned next: C, C++, Perl, Ruby - see
[`docs/sample-integration/roadmap.md`](sample-integration/roadmap.md).
