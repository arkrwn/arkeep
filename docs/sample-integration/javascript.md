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
