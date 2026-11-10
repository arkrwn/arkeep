#!/usr/bin/env node
// Smoke test for the TLS/TCP transport (server mode, ADR 0008): set a
// secret, read it back, confirm it round-trips, then confirm a denied
// path fails cleanly — over TLS, not the Unix socket. Run against a
// real daemon serving $MIKAVT_TLS_ADDR (see scripts/server-mode-smoke.sh,
// which generates a real self-signed CA + server cert and runs this for
// real). Uses the compiled dist/ output, proving the JavaScript
// consumption path (not just the TypeScript source) actually works.
//
// Usage: MIKAVT_TLS_ADDR=127.0.0.1:PORT MIKAVT_TLS_SERVER_NAME=name \
//   MIKAVT_TLS_CA=/path/ca.pem MIKAVT_TOKEN=<token> \
//   [MIKAVT_TLS_CLIENT_CERT=... MIKAVT_TLS_CLIENT_KEY=...] \
//   node examples/smoke_tls.js [allowed-path] [denied-path]

const { Client, DeniedError } = require("../dist/index.js");

function mustEnv(name) {
  const v = process.env[name];
  if (!v) {
    console.error(`${name} must be set`);
    process.exit(1);
  }
  return v;
}

async function main() {
  const addr = mustEnv("MIKAVT_TLS_ADDR");
  const serverName = mustEnv("MIKAVT_TLS_SERVER_NAME");
  const caCertPath = mustEnv("MIKAVT_TLS_CA");
  const token = mustEnv("MIKAVT_TOKEN");
  const clientCertPath = process.env.MIKAVT_TLS_CLIENT_CERT || undefined;
  const clientKeyPath = process.env.MIKAVT_TLS_CLIENT_KEY || undefined;

  const allowedPath = process.argv[2] || "sdk-smoke/javascript-tls";
  const deniedPath = process.argv[3] || "other/denied";

  const client = Client.connectTls({
    addr,
    serverName,
    caCertPath,
    clientCertPath,
    clientKeyPath,
  });

  const value = Buffer.from("javascript-sdk-tls-smoke-value");
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

  console.log("javascript SDK TLS (server mode) smoke test passed");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
