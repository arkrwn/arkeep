# Sample integration: TypeScript

Package: [`sdk/javascript/arkeep-sdk`](../../sdk/javascript/arkeep-sdk) —
written in TypeScript, Node's `net` module only, no runtime dependencies.
(Same package also works from plain JavaScript — see
[`javascript.md`](javascript.md).)

```bash
npm install ./sdk/javascript/arkeep-sdk
# (or, once published) npm install arkeep-sdk
```

```ts
import { Client, DeniedError } from "arkeep-sdk";

const client = new Client(process.env.ARKEEP_SOCKET!);
const token = process.env.ARKEEP_TOKEN!;

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
[`sdk/javascript/arkeep-sdk/examples/smoke.js`](../../sdk/javascript/arkeep-sdk/examples/smoke.js)
runs for real in CI (`scripts/sdk-smoke.sh`).

## Server mode (TLS / mutual TLS)

```ts
const client = Client.connectTls({
  addr: "arkeep.example.internal:8443",
  serverName: "arkeep.example.internal",
  caCertPath: "/path/to/ca.pem",
  // clientCertPath/clientKeyPath: set both together only if the server
  // requires mutual TLS ($ARKEEP_TLS_CLIENT_CA).
});
```

Uses Node's own `tls`/`fs` modules — no third-party TLS library. TLS 1.3
only (`minVersion`/`maxVersion` both `"TLSv1.3"`), `rejectUnauthorized`
is never set to `false` anywhere in this SDK, and passing `ca` to
`tls.connect` replaces Node's bundled public root store for this
connection rather than adding to it — this client trusts only the CA
you provide. Proven for real — including rejecting a wrong hostname,
rejecting a connection with no client cert against an mTLS-only server,
and rejecting a client cert signed by a different, untrusted CA — by
[`sdk/javascript/arkeep-sdk/examples/smoke_tls.js`](../../sdk/javascript/arkeep-sdk/examples/smoke_tls.js),
run by `scripts/server-mode-smoke.sh`.
