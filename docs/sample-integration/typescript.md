# Sample integration: TypeScript

Package: [`sdk/javascript/mikavt-sdk`](../../sdk/javascript/mikavt-sdk) —
written in TypeScript, Node's `net` module only, no runtime dependencies.
(Same package also works from plain JavaScript — see
[`javascript.md`](javascript.md).)

```bash
npm install ./sdk/javascript/mikavt-sdk
# (or, once published) npm install mikavt-sdk
```

```ts
import { Client, DeniedError } from "mikavt-sdk";

const client = new Client(process.env.MIKAVT_SOCKET!);
const token = process.env.MIKAVT_TOKEN!;

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
[`sdk/javascript/mikavt-sdk/examples/smoke.js`](../../sdk/javascript/mikavt-sdk/examples/smoke.js)
runs for real in CI (`scripts/sdk-smoke.sh`).
