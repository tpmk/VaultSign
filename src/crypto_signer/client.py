"""SignerClient — Python client for the crypto-signer daemon."""

import base64
import json
import socket
import uuid
from pathlib import Path

from .errors import SignerError, SignerConnectionError, IPCProtocolError

_HAS_AF_UNIX = hasattr(socket, "AF_UNIX")
_MAX_RESPONSE = 1048576  # 1 MB, matches server _MAX_MSG


def _default_socket_path() -> str:
    return str(Path.home() / ".crypto-signer" / "signer.sock")


class _ChainClient:
    """Chain-specific sub-client."""

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
        self._token: str | None = None

        if socket_path and not _HAS_AF_UNIX:
            # Windows: derive TCP connection info from port/token files
            self._resolve_tcp_from_socket_path(socket_path)
        elif not socket_path and not host:
            # Default to Unix socket if AF_UNIX is available
            if _HAS_AF_UNIX:
                self._socket_path = _default_socket_path()
            else:
                self._host = "127.0.0.1"
                self._port = 9473  # default TCP port

        self.evm = _ChainClient(self._send, "evm")

    def _resolve_tcp_from_socket_path(self, socket_path: str) -> None:
        """On Windows, read port/token files from the socket_path's directory."""
        sock_dir = Path(socket_path).parent
        port_file = sock_dir / "signer.port"
        token_file = sock_dir / "signer.token"

        try:
            self._port = int(port_file.read_text().strip())
        except (FileNotFoundError, ValueError) as e:
            raise SignerConnectionError(
                f"Cannot find signer port file ({port_file}): {e}"
            )

        try:
            self._token = token_file.read_text().strip()
        except FileNotFoundError as e:
            raise SignerConnectionError(
                f"Cannot find signer token file ({token_file}): {e}"
            )

        self._host = "127.0.0.1"
        self._socket_path = None  # Use TCP, not Unix

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
        if self._token:
            request["token"] = self._token
        s = self._connect()
        try:
            s.sendall((json.dumps(request) + "\n").encode())

            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > _MAX_RESPONSE:
                    raise IPCProtocolError("Response too large")
                if b"\n" in data:
                    break
        finally:
            s.close()

        if not data:
            raise IPCProtocolError("Empty response from signer")

        try:
            response = json.loads(data.decode().strip())
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise IPCProtocolError(f"Invalid response from signer: {e}") from e

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

    def get_key(self, name: str) -> str:
        """Retrieve a decrypted key by name.

        Returns the key as a string (the original value stored during add).
        """
        result = self._send("get_key", {"name": name})
        key_b64 = result["key"]
        return base64.b64decode(key_b64).decode("utf-8")
