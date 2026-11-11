# Sample integration: TypeScript

Package: [`sdk/javascript/cofferak-sdk`](../../sdk/javascript/cofferak-sdk) —
written in TypeScript, Node's `net` module only, no runtime dependencies.
(Same package also works from plain JavaScript — see
[`javascript.md`](javascript.md).)

```bash
npm install ./sdk/javascript/cofferak-sdk
# (or, once published) npm install cofferak-sdk
```

```ts
import { Client, DeniedError } from "cofferak-sdk";

const client = new Client(process.env.COFFERAK_SOCKET!);
const token = process.env.COFFERAK_TOKEN!;

await client.set(token, "myapp/DB_PASSWORD", Buffer.from("s3cr3t"));
const value = await client.get(token, "myapp/DB_PASSWORD");
console.log(value.toString());

try {
  await client.get(token, "someone-elses/SECRET");
} catch (e) {
  if (e instanceof DeniedError) console.log("correctly denied");
}
```

Build with `npm run build` (runs `tsc`); this exact flow — compiled to
plain JavaScript and run with `node` — is what
[`sdk/javascript/cofferak-sdk/examples/smoke.js`](../../sdk/javascript/cofferak-sdk/examples/smoke.js)
runs for real in CI (`scripts/sdk-smoke.sh`).

## Server mode (TLS / mutual TLS)

```ts
const client = Client.connectTls({
  addr: "cofferak.example.internal:8443",
  serverName: "cofferak.example.internal",
  caCertPath: "/path/to/ca.pem",
  // Mutual TLS is mandatory in cofferakd server mode (ADR 0011):
  clientCertPath: "/path/to/client.pem",
  clientKeyPath: "/path/to/client.key",
});
```

Uses Node's own `tls`/`fs` modules — no third-party TLS library. TLS 1.3
only (`minVersion`/`maxVersion` both `"TLSv1.3"`, cipher suite
`TLS_AES_256_GCM_SHA384` only), `rejectUnauthorized`
is never set to `false` anywhere in this SDK, and passing `ca` to
`tls.connect` replaces Node's bundled public root store for this
connection rather than adding to it — this client trusts only the CA
you provide. Proven for real — including rejecting a wrong hostname,
rejecting a connection with no client cert,
and rejecting a client cert signed by a different, untrusted CA — by
[`sdk/javascript/cofferak-sdk/examples/smoke_tls.js`](../../sdk/javascript/cofferak-sdk/examples/smoke_tls.js),
run by `scripts/server-mode-smoke.sh`.
