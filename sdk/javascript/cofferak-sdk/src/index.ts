/**
 * Minimal TypeScript/JavaScript client SDK for cofferak.
 *
 * Connects to a running `cofferakd` over its Unix socket and speaks the
 * same newline-delimited JSON protocol documented in
 * `cofferakd/src/protocol.rs` (`Request`/`Response`, serde's default
 * externally-tagged enum encoding). Node.js standard library only (`net`)
 * — no runtime dependencies.
 *
 * ```ts
 * import { Client } from "cofferak-sdk";
 *
 * const client = new Client("/run/cofferak/cofferakd.sock");
 * await client.set("my-token", "myapp/DB_PASSWORD", Buffer.from("s3cr3t"));
 * const value = await client.get("my-token", "myapp/DB_PASSWORD");
 * ```
 *
 * The compiled `dist/index.js` (CommonJS) works the same way from plain
 * JavaScript — this is one package serving both runtimes.
 */

import * as net from "node:net";

/** Base class for every error this SDK raises. */
export class CofferakError extends Error {}

/** The token doesn't have access to the requested path, or the token is
 * unknown to the daemon. */
export class DeniedError extends CofferakError {
  constructor() {
    super("denied");
    this.name = "DeniedError";
  }
}

/** The requested path has no value set. */
export class NotFoundError extends CofferakError {
  constructor() {
    super("not found");
    this.name = "NotFoundError";
  }
}

/** The daemon returned an error message. */
export class RemoteError extends CofferakError {
  constructor(message: string) {
    super(`remote error: ${message}`);
    this.name = "RemoteError";
  }
}

/** The daemon's response didn't match any known `Response` shape. */
export class ProtocolError extends CofferakError {
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

/**
 * A client connected to one cofferakd Unix socket. Each call opens a fresh
 * connection, matching the convention established by cofferakd's own CLI
 * client.
 */
export class Client {
  constructor(private readonly socketPath: string) {}

  private send(request: unknown): Promise<WireResponse> {
    return new Promise((resolve, reject) => {
      const sock = net.createConnection({ path: this.socketPath });
      let buf = "";
      let settled = false;

      sock.on("connect", () => {
        sock.write(JSON.stringify(request) + "\n");
      });
      sock.on("data", (chunk: Buffer) => {
        buf += chunk.toString("utf8");
        const idx = buf.indexOf("\n");
        if (idx !== -1 && !settled) {
          settled = true;
          sock.end();
          try {
            resolve(JSON.parse(buf.slice(0, idx)) as WireResponse);
          } catch (e) {
            reject(new ProtocolError(`invalid JSON response: ${(e as Error).message}`));
          }
        }
      });
      sock.on("error", (e) => {
        if (!settled) {
          settled = true;
          reject(e);
        }
      });
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
