"""Minimal Python client SDK for arkeep.

Connects to a running ``arkeepd`` over its Unix socket, or (server
mode, ADR 0008) over TLS-wrapped TCP, and speaks the same
newline-delimited JSON protocol documented in
``arkeepd/src/protocol.rs`` (``Request``/``Response``, serde's default
externally-tagged enum encoding). Standard library only — including
Python's own ``ssl`` module for the TLS transport, no third-party TLS
library.

Example::

    from arkeep_sdk import Client

    client = Client("/run/arkeep/arkeepd.sock")
    client.set("my-token", "myapp/DB_PASSWORD", b"s3cr3t")
    value = client.get("my-token", "myapp/DB_PASSWORD")
    assert value == b"s3cr3t"

Server mode::

    client = Client.connect_tls(
        addr="arkeep.example.internal:8443",
        server_name="arkeep.example.internal",
        ca_cert_path="/path/to/ca.pem",
    )
"""

from __future__ import annotations

import json
import socket as _socket
import ssl as _ssl
from typing import Any

# Mirrors arkeepd's protocol::MAX_LINE_BYTES (and the Rust/Go SDKs'
# identical constant) — a hard ceiling on one response line, so a
# malicious or compromised daemon that never terminates a response
# can't grow this client's buffer without limit.
_MAX_LINE_BYTES = 16 * 1024 * 1024

# Bounds how long one call can block on the network — a stalled or
# malicious daemon otherwise ties up the caller indefinitely. Matches
# arkeepd's own per-connection timeout (ADR 0008).
_IO_TIMEOUT_SECONDS = 30.0


class ArkeepError(Exception):
    """Base class for every error this SDK raises."""


class DeniedError(ArkeepError):
    """The token doesn't have access to the requested path, or the token
    is unknown to the daemon."""

    def __init__(self) -> None:
        super().__init__("denied")


class NotFoundError(ArkeepError):
    """The requested path has no value set."""

    def __init__(self) -> None:
        super().__init__("not found")


class RemoteError(ArkeepError):
    """The daemon returned an error message."""

    def __init__(self, message: str) -> None:
        super().__init__(f"remote error: {message}")
        self.message = message


class ProtocolError(ArkeepError):
    """The daemon's response didn't match any known ``Response`` shape,
    or exceeded this client's size limit."""


def _build_tls_context(
    ca_cert_path: str,
    client_cert_path: str | None,
    client_key_path: str | None,
) -> _ssl.SSLContext:
    # PROTOCOL_TLS_CLIENT pre-configures check_hostname=True and
    # verify_mode=CERT_REQUIRED (Python's own secure default for a
    # client context) — neither is weakened anywhere in this function.
    context = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = _ssl.TLSVersion.TLSv1_3
    context.maximum_version = _ssl.TLSVersion.TLSv1_3
    # Deliberately NOT calling load_default_certs(): this context's
    # trust store starts empty, and load_verify_locations below adds
    # ONLY the given CA. arkeep's TLS is for a self-managed deployment,
    # not the public web — this client must never also trust the OS's
    # public root store (that would let any public-CA-issued cert
    # impersonate the arkeep server).
    context.load_verify_locations(cafile=ca_cert_path)
    if client_cert_path or client_key_path:
        if not (client_cert_path and client_key_path):
            raise ValueError(
                "client_cert_path and client_key_path must both be set, or neither"
            )
        context.load_cert_chain(certfile=client_cert_path, keyfile=client_key_path)
    return context


class Client:
    """A client connected to one arkeepd endpoint — a Unix socket, or
    (server mode) a TLS/TCP address. Each call opens a fresh connection,
    matching the convention established by arkeepd's own CLI client."""

    def __init__(self, socket_path: str) -> None:
        self.socket_path: str | None = socket_path
        self._tls_addr: tuple[str, int] | None = None
        self._tls_server_name: str | None = None
        self._tls_context: _ssl.SSLContext | None = None

    @classmethod
    def connect_tls(
        cls,
        addr: str,
        server_name: str,
        ca_cert_path: str,
        client_cert_path: str | None = None,
        client_key_path: str | None = None,
    ) -> Client:
        """Build a client for the daemon's TLS/TCP listener (server
        mode, ADR 0008). ``addr`` is ``"host:port"``. Loads and
        validates the CA (and, if given, client cert/key) eagerly, so a
        misconfiguration fails here rather than on the first call."""
        host, _, port_str = addr.rpartition(":")
        if not host or not port_str.isdigit():
            raise ValueError(f"addr must be 'host:port', got {addr!r}")
        context = _build_tls_context(ca_cert_path, client_cert_path, client_key_path)

        instance = cls.__new__(cls)
        instance.socket_path = None
        instance._tls_addr = (host, int(port_str))
        instance._tls_server_name = server_name
        instance._tls_context = context
        return instance

    def _send(self, request: dict[str, Any]) -> Any:
        payload = (json.dumps(request) + "\n").encode("utf-8")
        if self.socket_path is not None:
            with _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM) as sock:
                sock.settimeout(_IO_TIMEOUT_SECONDS)
                sock.connect(self.socket_path)
                sock.sendall(payload)
                buf = self._read_line_bounded(sock)
        else:
            assert self._tls_addr is not None and self._tls_context is not None
            with _socket.create_connection(
                self._tls_addr, timeout=_IO_TIMEOUT_SECONDS
            ) as raw_sock:
                with self._tls_context.wrap_socket(
                    raw_sock, server_hostname=self._tls_server_name
                ) as tls_sock:
                    tls_sock.settimeout(_IO_TIMEOUT_SECONDS)
                    tls_sock.sendall(payload)
                    buf = self._read_line_bounded(tls_sock)
        try:
            return json.loads(buf.decode("utf-8"))
        except json.JSONDecodeError as e:
            raise ProtocolError(f"invalid JSON response: {e}") from e

    @staticmethod
    def _read_line_bounded(sock: Any) -> bytes:
        """Read until ``\\n`` or ``_MAX_LINE_BYTES``, whichever comes
        first — never growing the buffer past that limit. Each call
        makes exactly one request and expects exactly one response line
        before the connection closes, so there's no "next request" to
        preserve across calls."""
        buf = b""
        while b"\n" not in buf:
            chunk = sock.recv(65536)
            if not chunk:
                break
            if len(buf) + len(chunk) > _MAX_LINE_BYTES:
                raise ProtocolError("response line exceeded the maximum allowed size")
            buf += chunk
        return buf

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
    "ArkeepError",
    "DeniedError",
    "NotFoundError",
    "RemoteError",
    "ProtocolError",
]
