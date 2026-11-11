#!/usr/bin/env python3
"""Smoke test for the TLS/TCP transport (server mode, ADR 0008): set a
secret, read it back, confirm it round-trips, then confirm a denied path
fails cleanly - over TLS, not the Unix socket. Run against a real daemon
serving $COFFERAK_TLS_ADDR (see scripts/server-mode-smoke.sh, which
generates a real self-signed CA + server cert and runs this for real).

Usage: COFFERAK_TLS_ADDR=127.0.0.1:PORT COFFERAK_TLS_SERVER_NAME=name \
    COFFERAK_TLS_CA=/path/ca.pem COFFERAK_TOKEN=<token> \
    [COFFERAK_TLS_CLIENT_CERT=... COFFERAK_TLS_CLIENT_KEY=...] \
    python3 examples/smoke_tls.py [allowed-path] [denied-path]
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cofferak_sdk import Client, DeniedError  # noqa: E402


def env_required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        print(f"{name} must be set", file=sys.stderr)
        sys.exit(1)
    return value


def main() -> int:
    addr = env_required("COFFERAK_TLS_ADDR")
    server_name = env_required("COFFERAK_TLS_SERVER_NAME")
    ca_cert_path = env_required("COFFERAK_TLS_CA")
    token = env_required("COFFERAK_TOKEN")
    client_cert_path = os.environ.get("COFFERAK_TLS_CLIENT_CERT") or None
    client_key_path = os.environ.get("COFFERAK_TLS_CLIENT_KEY") or None

    allowed_path = sys.argv[1] if len(sys.argv) > 1 else "sdk-smoke/python-tls"
    denied_path = sys.argv[2] if len(sys.argv) > 2 else "other/denied"

    client = Client.connect_tls(
        addr=addr,
        server_name=server_name,
        ca_cert_path=ca_cert_path,
        client_cert_path=client_cert_path,
        client_key_path=client_key_path,
    )

    value = b"python-sdk-tls-smoke-value"
    client.set(token, allowed_path, value)
    got = client.get(token, allowed_path)
    assert got == value, f"round-tripped value mismatch: got {got!r}, want {value!r}"

    try:
        client.get(token, denied_path)
        raise AssertionError("expected DeniedError for a path outside the token's prefix")
    except DeniedError:
        pass

    print("python SDK TLS (server mode) smoke test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
