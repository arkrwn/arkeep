# Sample integration: JavaScript

Same package as [TypeScript](typescript.md) -
[`sdk/javascript/cofferak-sdk`](https://github.com/arkrwn/cofferak/tree/main/sdk/javascript/cofferak-sdk) - consumed
from plain JavaScript via its compiled `dist/index.js` (CommonJS), no
build step needed on the consuming side.

```bash
npm install ./sdk/javascript/cofferak-sdk
# (or, once published) npm install cofferak-sdk
```

```js
const { Client, DeniedError } = require("cofferak-sdk");

async function main() {
  const client = new Client(process.env.COFFERAK_SOCKET);
  const token = process.env.COFFERAK_TOKEN;

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
[`sdk/javascript/cofferak-sdk/examples/smoke.js`](https://github.com/arkrwn/cofferak/blob/main/sdk/javascript/cofferak-sdk/examples/smoke.js)
runs for real in CI (`scripts/sdk-smoke.sh`), against the actual compiled
`dist/` output - proving the JavaScript consumption path, not just the
TypeScript source.

## Server mode over mutual TLS

```js
const client = Client.connectTls({
  addr: "cofferak.example.internal:8443",
  serverName: "cofferak.example.internal",
  caCertPath: "/path/to/ca.pem",
  // Mutual TLS is mandatory in cofferakd server mode (ADR 0011):
  clientCertPath: "/path/to/client.pem",
  clientKeyPath: "/path/to/client.key",
});
```

Same hardening as the [TypeScript page](typescript.md#server-mode-over-mutual-tls)
(TLS 1.3 only, no public-root fallback, `rejectUnauthorized` never
disabled) - this is the same compiled code. Proven for real against the
compiled `dist/` output by
[`sdk/javascript/cofferak-sdk/examples/smoke_tls.js`](https://github.com/arkrwn/cofferak/blob/main/sdk/javascript/cofferak-sdk/examples/smoke_tls.js),
run by `scripts/server-mode-smoke.sh`.
