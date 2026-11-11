/**
 * Minimal TypeScript/JavaScript client SDK for mikavt.
 *
 * Connects to a running `mikavtd` over its Unix socket, or (server
 * mode, ADR 0008) over TLS-wrapped TCP, and speaks the same
 * newline-delimited JSON protocol documented in
 * `mikavtd/src/protocol.rs` (`Request`/`Response`, serde's default
 * externally-tagged enum encoding). Node.js standard library only
 * (`net`, `tls`, `fs`) — no runtime dependencies, including for TLS.
 *
 * ```ts
 * import { Client } from "mikavt-sdk";
 *
 * const client = new Client("/run/mikavt/mikavtd.sock");
 * await client.set("my-token", "myapp/DB_PASSWORD", Buffer.from("s3cr3t"));
 * const value = await client.get("my-token", "myapp/DB_PASSWORD");
 * ```
 *
 * Server mode:
 *
 * ```ts
 * const client = Client.connectTls({
 *   addr: "mikavt.example.internal:8443",
 *   serverName: "mikavt.example.internal",
 *   caCertPath: "/path/to/ca.pem",
 * });
 * ```
 *
 * The compiled `dist/index.js` (CommonJS) works the same way from plain
 * JavaScript — this is one package serving both runtimes.
 */

import * as fs from "node:fs";
import * as net from "node:net";
import * as tls from "node:tls";

/** Mirrors mikavtd's `protocol::MAX_LINE_BYTES` (and the Rust/Go/Python
 * SDKs' identical constant) — a hard ceiling on one response line, so a
 * malicious or compromised daemon that never terminates a response
 * can't grow this client's buffer without limit. */
const MAX_LINE_BYTES = 16 * 1024 * 1024;

/** Bounds how long one call can block on the network — a stalled or
 * malicious daemon otherwise ties up the caller indefinitely. Matches
 * mikavtd's own per-connection timeout (ADR 0008). */
const IO_TIMEOUT_MS = 30_000;

/** Base class for every error this SDK raises. */
export class MikavtError extends Error {}

/** The token doesn't have access to the requested path, or the token is
 * unknown to the daemon. */
export class DeniedError extends MikavtError {
  constructor() {
    super("denied");
    this.name = "DeniedError";
  }
}

/** The requested path has no value set. */
export class NotFoundError extends MikavtError {
  constructor() {
    super("not found");
    this.name = "NotFoundError";
  }
}

/** The daemon returned an error message. */
export class RemoteError extends MikavtError {
  constructor(message: string) {
    super(`remote error: ${message}`);
    this.name = "RemoteError";
  }
}

/** The daemon's response didn't match any known `Response` shape, or
 * exceeded this client's size limit. */
export class ProtocolError extends MikavtError {
  constructor(message: string) {
    super(`protocol error: ${message}`);
    this.name = "ProtocolError";
  }
}

type WireResponse =
  | { Value: number[] }
  | { Listed: string[] }
  | { Err: string }
  | "Ok"
  | "Denied"
  | "NotFound";

/** Options for connecting over TLS/TCP (server mode, ADR 0008) instead
 * of the Unix socket. */
export interface TlsOptions {
  /** `"host:port"` to connect to (matches the daemon's `$MIKAVT_TLS_ADDR`). */
  addr: string;
  /** Verified against the server's certificate (its subject/SAN) — this
   * is NOT where you disable verification; there is no option to do
   * that in this SDK. */
  serverName: string;
  /** PEM file containing the CA that signed the server's certificate.
   * mikavt's TLS is for a self-managed deployment, not the public web —
   * this client trusts ONLY this CA, never Node's bundled public root
   * store (passing `ca` to `tls.connect` replaces the default trust
   * store rather than adding to it). */
  caCertPath: string;
  /** Client certificate + private key (PEM), both set together, enable
   * mutual TLS — required only if the server was started with
   * `$MIKAVT_TLS_CLIENT_CA`. */
  clientCertPath?: string;
  clientKeyPath?: string;
}

type Transport =
  | { kind: "unix"; socketPath: string }
  | {
      kind: "tls";
      host: string;
      port: number;
      serverName: string;
      ca: Buffer;
      cert?: Buffer;
      key?: Buffer;
    };

/**
 * A client connected to one mikavtd endpoint — a Unix socket, or
 * (server mode) a TLS/TCP address. Each call opens a fresh connection,
 * matching the convention established by mikavtd's own CLI client.
 */
export class Client {
  private readonly transport: Transport;

  constructor(socketPath: string) {
    this.transport = { kind: "unix", socketPath };
  }

  private static fromTransport(transport: Transport): Client {
    // Bypasses the public (Unix-socket) constructor entirely — there is
    // no intermediate "empty"/placeholder Client ever created.
    const client = Object.create(Client.prototype) as Client;
    (client as unknown as { transport: Transport }).transport = transport;
    return client;
  }

  /** Build a client for the daemon's TLS/TCP listener (server mode,
   * ADR 0008). Loads the CA (and, if given, client cert/key) eagerly,
   * so a misconfiguration fails here rather than on the first call. */
  static connectTls(options: TlsOptions): Client {
    const [host, portStr] = splitHostPort(options.addr);
    const ca = fs.readFileSync(options.caCertPath);
    let cert: Buffer | undefined;
    let key: Buffer | undefined;
    if (options.clientCertPath || options.clientKeyPath) {
      if (!options.clientCertPath || !options.clientKeyPath) {
        throw new Error("clientCertPath and clientKeyPath must both be set, or neither");
      }
      cert = fs.readFileSync(options.clientCertPath);
      key = fs.readFileSync(options.clientKeyPath);
    }
    return Client.fromTransport({
      kind: "tls",
      host,
      port: Number(portStr),
      serverName: options.serverName,
      ca,
      cert,
      key,
    });
  }

  private send(request: unknown): Promise<WireResponse> {
    return new Promise((resolve, reject) => {
      const transport = this.transport;
      const sock: net.Socket =
        transport.kind === "tls"
          ? tls.connect({
              host: transport.host,
              port: transport.port,
              servername: transport.serverName,
              ca: transport.ca,
              cert: transport.cert,
              key: transport.key,
              minVersion: "TLSv1.3",
              maxVersion: "TLSv1.3",
              // rejectUnauthorized defaults to true and is never set to
              // false anywhere in this SDK — that is the one setting
              // that would disable certificate verification.
            })
          : net.createConnection({ path: transport.socketPath });

      let buf = Buffer.alloc(0);
      let settled = false;

      const fail = (err: Error) => {
        if (settled) return;
        settled = true;
        sock.destroy();
        reject(err);
      };
      const succeed = (value: WireResponse) => {
        if (settled) return;
        settled = true;
        sock.end();
        resolve(value);
      };

      sock.setTimeout(IO_TIMEOUT_MS, () => fail(new Error("timed out")));

      sock.on("connect", () => {
        sock.write(JSON.stringify(request) + "\n");
      });
      // For the TLS transport `connect` fires on the underlying TCP
      // socket before the handshake completes; writing the request is
      // deferred to `secureConnect` there instead.
      if (transport.kind === "tls") {
        (sock as tls.TLSSocket).on("secureConnect", () => {
          sock.write(JSON.stringify(request) + "\n");
        });
      }
      sock.on("data", (chunk: Buffer) => {
        if (settled) return;
        if (buf.length + chunk.length > MAX_LINE_BYTES) {
          fail(new ProtocolError("response line exceeded the maximum allowed size"));
          return;
        }
        buf = Buffer.concat([buf, chunk]);
        const idx = buf.indexOf(0x0a); // '\n'
        if (idx !== -1) {
          try {
            succeed(JSON.parse(buf.subarray(0, idx).toString("utf8")) as WireResponse);
          } catch (e) {
            fail(new ProtocolError(`invalid JSON response: ${(e as Error).message}`));
          }
        }
      });
      sock.on("error", (e) => fail(e));
    });
  }

  private static checkOk(response: WireResponse): void {
    if (response === "Ok") return;
    if (response === "Denied") throw new DeniedError();
    if (response === "NotFound") throw new NotFoundError();
    if (typeof response === "object" && "Err" in response) {
      throw new RemoteError(response.Err);
    }
    throw new ProtocolError(
      `unexpected response to a write/delete request: ${JSON.stringify(response)}`
    );
  }

  /** Read a secret's value. */
  async get(token: string, path: string): Promise<Buffer> {
    const response = await this.send({ Get: { token, path } });
    if (typeof response === "object" && "Value" in response) {
      return Buffer.from(response.Value);
    }
    if (response === "Denied") throw new DeniedError();
    if (response === "NotFound") throw new NotFoundError();
    if (typeof response === "object" && "Err" in response) {
      throw new RemoteError(response.Err);
    }
    throw new ProtocolError(`unexpected response to Get: ${JSON.stringify(response)}`);
  }

  /** Write a secret's value. Requires a read-write token. */
  async set(token: string, path: string, value: Uint8Array): Promise<void> {
    const response = await this.send({
      Set: { token, path, value: Array.from(value) },
    });
    Client.checkOk(response);
  }

  /** Remove a secret. Requires a read-write token. */
  async rm(token: string, path: string): Promise<void> {
    const response = await this.send({ Rm: { token, path } });
    Client.checkOk(response);
  }

  /** List secret paths under `prefix`. */
  async list(token: string, prefix: string): Promise<string[]> {
    const response = await this.send({ List: { token, prefix } });
    if (typeof response === "object" && "Listed" in response) {
      return response.Listed;
    }
    if (response === "Denied") throw new DeniedError();
    if (typeof response === "object" && "Err" in response) {
      throw new RemoteError(response.Err);
    }
    throw new ProtocolError(`unexpected response to List: ${JSON.stringify(response)}`);
  }
}

function splitHostPort(addr: string): [string, string] {
  const idx = addr.lastIndexOf(":");
  if (idx === -1) {
    throw new Error(`addr must be "host:port", got ${JSON.stringify(addr)}`);
  }
  return [addr.slice(0, idx), addr.slice(idx + 1)];
}
