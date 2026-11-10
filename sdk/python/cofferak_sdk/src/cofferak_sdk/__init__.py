"""Minimal Python client SDK for cofferak.

Connects to a running ``cofferakd`` over its Unix socket and speaks the
same newline-delimited JSON protocol documented in
``cofferakd/src/protocol.rs`` (``Request``/``Response``, serde's default
externally-tagged enum encoding). Standard library only — no
dependencies.

Example::

    from cofferak_sdk import Client

    client = Client("/run/cofferak/cofferakd.sock")
    client.set("my-token", "myapp/DB_PASSWORD", b"s3cr3t")
    value = client.get("my-token", "myapp/DB_PASSWORD")
    assert value == b"s3cr3t"
"""

from __future__ import annotations

import json
import socket as _socket
from typing import Any


class CofferakError(Exception):
    """Base class for every error this SDK raises."""


class DeniedError(CofferakError):
    """The token doesn't have access to the requested path, or the token
    is unknown to the daemon."""

    def __init__(self) -> None:
        super().__init__("denied")


class NotFoundError(CofferakError):
    """The requested path has no value set."""

    def __init__(self) -> None:
        super().__init__("not found")


class RemoteError(CofferakError):
    """The daemon returned an error message."""

    def __init__(self, message: str) -> None:
        super().__init__(f"remote error: {message}")
        self.message = message


class ProtocolError(CofferakError):
    """The daemon's response didn't match any known ``Response`` shape."""


class Client:
    """A client connected to one cofferakd Unix socket. Each call opens a
    fresh connection, matching the convention established by cofferakd's
    own CLI client."""

    def __init__(self, socket_path: str) -> None:
        self.socket_path = socket_path

    def _send(self, request: dict[str, Any]) -> Any:
        with _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM) as sock:
            sock.connect(self.socket_path)
            sock.sendall((json.dumps(request) + "\n").encode("utf-8"))
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
        try:
            return json.loads(buf.decode("utf-8"))
        except json.JSONDecodeError as e:
            raise ProtocolError(f"invalid JSON response: {e}") from e

    @staticmethod
    def _check_ok(response: Any) -> None:
        if response == "Ok":
            return
        if response == "Denied":
            raise DeniedError()
        if response == "NotFound":
            raise NotFoundError()
        if isinstance(response, dict) and "Err" in response:
            raise RemoteError(response["Err"])
        raise ProtocolError(f"unexpected response to a write/delete request: {response!r}")

    def get(self, token: str, path: str) -> bytes:
        """Read a secret's value."""
        response = self._send({"Get": {"token": token, "path": path}})
        if isinstance(response, dict) and "Value" in response:
            return bytes(response["Value"])
        if response == "Denied":
            raise DeniedError()
        if response == "NotFound":
            raise NotFoundError()
        if isinstance(response, dict) and "Err" in response:
            raise RemoteError(response["Err"])
        raise ProtocolError(f"unexpected response to Get: {response!r}")

    def set(self, token: str, path: str, value: bytes) -> None:
        """Write a secret's value. Requires a read-write token."""
        response = self._send(
            {"Set": {"token": token, "path": path, "value": list(value)}}
        )
        self._check_ok(response)

    def rm(self, token: str, path: str) -> None:
        """Remove a secret. Requires a read-write token."""
        response = self._send({"Rm": {"token": token, "path": path}})
        self._check_ok(response)

    def list(self, token: str, prefix: str) -> list[str]:
        """List secret paths under ``prefix``."""
        response = self._send({"List": {"token": token, "prefix": prefix}})
        if isinstance(response, dict) and "Listed" in response:
            return list(response["Listed"])
        if response == "Denied":
            raise DeniedError()
        if isinstance(response, dict) and "Err" in response:
            raise RemoteError(response["Err"])
        raise ProtocolError(f"unexpected response to List: {response!r}")


__all__ = [
    "Client",
    "CofferakError",
    "DeniedError",
    "NotFoundError",
    "RemoteError",
    "ProtocolError",
]
