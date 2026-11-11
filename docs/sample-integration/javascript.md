# Sample integration: JavaScript

Same package as [TypeScript](typescript.md) —
[`sdk/javascript/mikavt-sdk`](../../sdk/javascript/mikavt-sdk) — consumed
from plain JavaScript via its compiled `dist/index.js` (CommonJS), no
build step needed on the consuming side.

```bash
npm install ./sdk/javascript/mikavt-sdk
# (or, once published) npm install mikavt-sdk
```

```js
const { Client, DeniedError } = require("mikavt-sdk");

async function main() {
  const client = new Client(process.env.MIKAVT_SOCKET);
  const token = process.env.MIKAVT_TOKEN;

  await client.set(token, "myapp/DB_PASSWORD", Buffer.from("s3cr3t"));
  const value = await client.get(token, "myapp/DB_PASSWORD");
  console.log(value.toString());

  try {
    await client.get(token, "someone-elses/SECRET");
  } catch (e) {
    if (e instanceof DeniedError) console.log("correctly denied");
  }
}

main();
```

This exact flow is what
[`sdk/javascript/mikavt-sdk/examples/smoke.js`](../../sdk/javascript/mikavt-sdk/examples/smoke.js)
runs for real in CI (`scripts/sdk-smoke.sh`), against the actual compiled
`dist/` output — proving the JavaScript consumption path, not just the
TypeScript source.

## Server mode (TLS / mutual TLS)

```js
const client = Client.connectTls({
  addr: "mikavt.example.internal:8443",
  serverName: "mikavt.example.internal",
  caCertPath: "/path/to/ca.pem",
  // clientCertPath/clientKeyPath: set both together only if the server
  // requires mutual TLS ($MIKAVT_TLS_CLIENT_CA).
});
```

Same hardening as the [TypeScript page](typescript.md#server-mode-tls--mutual-tls)
(TLS 1.3 only, no public-root fallback, `rejectUnauthorized` never
disabled) — this is the same compiled code. Proven for real against the
compiled `dist/` output by
[`sdk/javascript/mikavt-sdk/examples/smoke_tls.js`](../../sdk/javascript/mikavt-sdk/examples/smoke_tls.js),
run by `scripts/server-mode-smoke.sh`.
