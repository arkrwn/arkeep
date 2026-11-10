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
