"""SignerClient — Python client for the crypto-signer daemon."""

import json
import socket
import uuid
from pathlib import Path

from .errors import SignerError, SignerConnectionError

_HAS_AF_UNIX = hasattr(socket, "AF_UNIX")


def _default_socket_path() -> str:
    return str(Path.home() / ".crypto-signer" / "signer.sock")


class _ChainClient:
    """Chain-specific sub-client (evm or solana)."""

    def __init__(self, send_fn, chain: str):
        self._send = send_fn
        self._chain = chain

    def get_address(self) -> str:
        result = self._send("get_address", {"chain": self._chain})
        return result["address"]

    def sign_transaction(self, tx) -> dict:
        return self._send("sign_transaction", {"chain": self._chain, "tx": tx})

    def sign_message(self, message) -> dict:
        return self._send("sign_message", {"chain": self._chain, "message": message})

    def sign_typed_data(self, domain: dict, types: dict, value: dict) -> dict:
        return self._send(
            "sign_typed_data",
            {"chain": self._chain, "domain": domain, "types": types, "value": value},
        )


class SignerClient:
    """Client for communicating with the crypto-signer daemon.

    Supports both Unix domain sockets and TCP connections.
    - On Unix: pass socket_path
    - On Windows: pass host and port
    """

    def __init__(
        self,
        socket_path: str | None = None,
        host: str | None = None,
        port: int | None = None,
    ):
        self._socket_path = socket_path
        self._host = host
        self._port = port

        # Default to Unix socket if nothing specified and AF_UNIX is available
        if not socket_path and not host:
            if _HAS_AF_UNIX:
                self._socket_path = _default_socket_path()
            else:
                self._host = "127.0.0.1"
                self._port = 9473  # default TCP port

        self.evm = _ChainClient(self._send, "evm")
        self.solana = _ChainClient(self._send, "solana")

    def _connect(self) -> socket.socket:
        """Create and connect a socket."""
        try:
            if self._socket_path and _HAS_AF_UNIX:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(30.0)
                s.connect(self._socket_path)
                return s
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(30.0)
                s.connect((self._host, self._port))
                return s
        except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
            raise SignerConnectionError(f"Cannot connect to signer: {e}")

    def _send(self, method: str, params: dict | None = None) -> dict:
        request = {
            "version": 1,
            "id": str(uuid.uuid4())[:8],
            "method": method,
            "params": params or {},
        }
        s = self._connect()
        try:
            s.sendall((json.dumps(request) + "\n").encode())

            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break
        finally:
            s.close()

        response = json.loads(data.decode().strip())

        if "error" in response:
            raise SignerError.from_dict(response["error"])

        return response.get("result", {})

    def ping(self) -> dict:
        return self._send("ping")

    def status(self) -> dict:
        return self._send("status")

    def lock(self) -> dict:
        return self._send("lock")

    def unlock(self, password: str, timeout: int = 0) -> dict:
        return self._send("unlock", {"password": password, "timeout": timeout})
