#!/usr/bin/env python3
"""Smoke test: set a secret, read it back, confirm it round-trips, then
confirm a denied path fails cleanly. Run against a real cofferakd (see
scripts/sdk-smoke.sh, which bootstraps one and runs this for real — this
is not a mocked test).

Usage: COFFERAK_SOCKET=/path/to.sock COFFERAK_TOKEN=<token> \
    python3 examples/smoke.py [allowed-path] [denied-path]
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cofferak_sdk import Client, DeniedError  # noqa: E402


def main() -> int:
    socket_path = os.environ.get("COFFERAK_SOCKET")
    token = os.environ.get("COFFERAK_TOKEN")
    if not socket_path or not token:
        print("COFFERAK_SOCKET and COFFERAK_TOKEN must be set", file=sys.stderr)
        return 1

    allowed_path = sys.argv[1] if len(sys.argv) > 1 else "sdk-smoke/python"
    denied_path = sys.argv[2] if len(sys.argv) > 2 else "other/denied"

    client = Client(socket_path)
    value = b"python-sdk-smoke-value"

    client.set(token, allowed_path, value)
    got = client.get(token, allowed_path)
    assert got == value, f"round-tripped value mismatch: got {got!r}, want {value!r}"

    try:
        client.get(token, denied_path)
        raise AssertionError("expected DeniedError for a path outside the token's prefix")
    except DeniedError:
        pass

    print("python SDK smoke test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
