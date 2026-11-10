#!/usr/bin/env node
// Smoke test: set a secret, read it back, confirm it round-trips, then
// confirm a denied path fails cleanly. Run against a real mikavtd (see
// scripts/sdk-smoke.sh, which bootstraps one and runs this for real —
// this is not a mocked test).
//
// Usage: MIKAVT_SOCKET=/path/to.sock MIKAVT_TOKEN=<token> \
//   node examples/smoke.js [allowed-path] [denied-path]
//
// Uses the compiled dist/ output, proving the JavaScript consumption
// path (not just the TypeScript source) actually works.

const { Client, DeniedError } = require("../dist/index.js");

async function main() {
  const socketPath = process.env.MIKAVT_SOCKET;
  const token = process.env.MIKAVT_TOKEN;
  if (!socketPath || !token) {
    console.error("MIKAVT_SOCKET and MIKAVT_TOKEN must be set");
    process.exit(1);
  }

  const allowedPath = process.argv[2] || "sdk-smoke/javascript";
  const deniedPath = process.argv[3] || "other/denied";

  const client = new Client(socketPath);
  const value = Buffer.from("javascript-sdk-smoke-value");

  await client.set(token, allowedPath, value);
  const got = await client.get(token, allowedPath);
  if (!got.equals(value)) {
    console.error(`round-tripped value mismatch: got ${got}, want ${value}`);
    process.exit(1);
  }

  try {
    await client.get(token, deniedPath);
    console.error("expected DeniedError for a path outside the token's prefix");
    process.exit(1);
  } catch (e) {
    if (!(e instanceof DeniedError)) {
      console.error("expected DeniedError, got", e);
      process.exit(1);
    }
  }

  console.log("javascript SDK smoke test passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
