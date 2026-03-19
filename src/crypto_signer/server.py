# src/crypto_signer/server.py
"""IPC signing server.

Uses Unix domain sockets on Linux/macOS and TCP localhost on Windows.
"""

import base64
import json
import logging
import os
import socket
import sys
import threading
import time

from .config import Config
from .errors import (
    IPCProtocolError,
    InvalidPasswordError,
    KeyNotFoundError,
    PermissionDeniedError,
    PolicyViolationError,
    SignerError,
    SignerStateError,
    UnsupportedChainError,
)
from .keystore import Keystore, KeyEntry
from .crypto.evm import EVMSigner
from .security.harden import apply_hardening, lock_key_memory
from .security.platform import set_file_owner_only
from .security.zeroize import zeroize
from .state import SignerState, SignerStateMachine

logger = logging.getLogger(__name__)

_HAS_AF_UNIX = hasattr(socket, "AF_UNIX")

_MAX_MSG = 1048576  # 1 MB default


class SignerServer:
    def __init__(self, config: Config):
        self.config = config
        self._sm = SignerStateMachine()
        self._keystore: Keystore | None = None
        self._evm: EVMSigner | None = None
        self._socket: socket.socket | None = None
        self._running = False
        self._start_time = time.time()
        self._unlock_ttl: float | None = None
        self._ttl_timer: threading.Timer | None = None
        self._unlock_failures = 0
        self._next_unlock_allowed = 0.0  # timestamp for backoff
        self._sign_count = 0
        self._rate_window_start = time.time()
        self._lock = threading.Lock()
        # On Windows (TCP mode), store the (host, port) after binding
        self.server_address: tuple[str, int] | None = None
        self._tcp_mode = False
        self._tcp_token: str | None = None
        self._decrypted_keys: dict[str, KeyEntry] = {}

    def load_keystore(self) -> None:
        self._keystore = Keystore.load(self.config.keystore_path)
        self._sm.transition_to(SignerState.LOCKED)

    def unlock(self, password: bytearray, timeout: int = 0) -> None:
        with self._lock:
            if self._sm.state == SignerState.UNLOCKED:
                raise SignerStateError("Already unlocked")

            if self._unlock_failures >= self.config.max_unlock_attempts:
                raise PolicyViolationError(
                    "Max unlock attempts exceeded. Restart the service."
                )

            # Backoff: reject if called too soon after a failure
            now = time.time()
            if now < self._next_unlock_allowed:
                remaining = int(self._next_unlock_allowed - now)
                raise PolicyViolationError(
                    f"Backoff active. Retry in {remaining}s."
                )

            try:
                keys = self._keystore.decrypt_all(password)
            except InvalidPasswordError:
                self._unlock_failures += 1
                delay = min(2 ** (self._unlock_failures - 1), 16)
                self._next_unlock_allowed = time.time() + delay
                raise
            finally:
                zeroize(password)

            self._unlock_failures = 0

            for key in keys:
                if self.config.try_mlock and key.private_key:
                    lock_key_memory(key.private_key)

                if key.key_type == "secp256k1":
                    self._evm = EVMSigner(key.private_key)

                # Store all keys by name for get_key
                self._decrypted_keys[key.name] = key

            self._sm.transition_to(SignerState.UNLOCKED)

            if timeout > 0:
                self._unlock_ttl = time.time() + timeout
                self._ttl_timer = threading.Timer(timeout, self._auto_lock)
                self._ttl_timer.daemon = True
                self._ttl_timer.start()

    def lock(self) -> None:
        with self._lock:
            if self._ttl_timer:
                self._ttl_timer.cancel()
                self._ttl_timer = None
            self._unlock_ttl = None
            if self._evm:
                self._evm.zeroize()
                self._evm = None
            # Zeroize all decrypted keys
            for key in self._decrypted_keys.values():
                if key.private_key:
                    zeroize(key.private_key)
            self._decrypted_keys.clear()
            if self._sm.state == SignerState.UNLOCKED:
                self._sm.transition_to(SignerState.LOCKED)

    def _auto_lock(self) -> None:
        logger.info("TTL expired, auto-locking")
        self.lock()

    def _check_rate_limit(self) -> None:
        with self._lock:
            now = time.time()
            if now - self._rate_window_start >= 60:
                self._sign_count = 0
                self._rate_window_start = now
            self._sign_count += 1
            if self._sign_count > self.config.rate_limit:
                raise PolicyViolationError("Rate limit exceeded")

    def _handle_request(self, data: bytes) -> bytes:
        try:
            text = data.decode("utf-8").strip()
            if len(text) > self.config.max_request_size:
                err = IPCProtocolError("Request too large")
                return (json.dumps({"id": None, "error": err.to_dict()}) + "\n").encode()
            request = json.loads(text)
        except (json.JSONDecodeError, UnicodeDecodeError):
            err = IPCProtocolError("Invalid JSON")
            return (json.dumps({"id": None, "error": err.to_dict()}) + "\n").encode()

        if not isinstance(request, dict):
            err = IPCProtocolError("Invalid JSON")
            return (json.dumps({"id": None, "error": err.to_dict()}) + "\n").encode()

        req_id = request.get("id")
        version = request.get("version")
        if version != 1:
            err = IPCProtocolError(f"Unsupported protocol version: {version}")
            return (json.dumps({"id": req_id, "error": err.to_dict()}) + "\n").encode()

        # TCP token auth
        if self._tcp_mode:
            token = request.get("token")
            if token != self._tcp_token:
                err = PermissionDeniedError("Invalid or missing auth token")
                return (json.dumps({"id": req_id, "error": err.to_dict()}) + "\n").encode()

        method = request.get("method", "")
        params = request.get("params", {})

        if not isinstance(params, dict):
            err = IPCProtocolError("params must be an object")
            return (json.dumps({"id": req_id, "error": err.to_dict()}) + "\n").encode()

        try:
            result = self._dispatch(method, params)
            return (json.dumps({"id": req_id, "result": result}) + "\n").encode()
        except SignerError as e:
            return (json.dumps({"id": req_id, "error": e.to_dict()}) + "\n").encode()
        except Exception:
            logger.error("Unexpected error handling %s", method, exc_info=True)
            err = IPCProtocolError("Internal error")
            return (json.dumps({"id": req_id, "error": err.to_dict()}) + "\n").encode()

    def _dispatch(self, method: str, params: dict) -> dict:
        handlers = {
            "ping": self._handle_ping,
            "status": self._handle_status,
            "unlock": self._handle_unlock,
            "lock": self._handle_lock,
            "shutdown": self._handle_shutdown,
            "get_key": self._handle_get_key,
            "get_address": self._handle_get_address,
            "sign_transaction": self._handle_sign_transaction,
            "sign_message": self._handle_sign_message,
            "sign_typed_data": self._handle_sign_typed_data,
        }
        handler = handlers.get(method)
        if not handler:
            raise IPCProtocolError(f"Unknown method: {method}")
        return handler(params)

    def _handle_ping(self, params: dict) -> dict:
        return {"status": "ok"}

    def _handle_status(self, params: dict) -> dict:
        result = {
            "state": self._sm.state.value,
            "uptime": int(time.time() - self._start_time),
        }
        if self._unlock_ttl:
            remaining = max(0, int(self._unlock_ttl - time.time()))
            result["ttl_remaining"] = remaining
        return result

    def _handle_unlock(self, params: dict) -> dict:
        password = params.get("password", "")
        timeout = params.get("timeout", 0)
        pwd_buf = bytearray(password.encode("utf-8"))
        self.unlock(pwd_buf, timeout)
        return {"status": "unlocked"}

    def _handle_lock(self, params: dict) -> dict:
        self.lock()
        return {"status": "locked"}

    def _handle_shutdown(self, params: dict) -> dict:
        self.lock()
        self._running = False
        return {"status": "shutting_down"}

    def _get_chain_signer(self, chain: str):
        """Get the signer for a chain, raising clear errors if unavailable."""
        self._sm.require_unlocked()
        if chain == "evm":
            if self._evm is None:
                raise UnsupportedChainError("No EVM key loaded")
            return self._evm
        raise UnsupportedChainError(f"Unsupported chain: {chain}")

    def _handle_get_key(self, params: dict) -> dict:
        self._check_rate_limit()
        self._sm.require_unlocked()
        name = params.get("name", "")
        if not name:
            raise IPCProtocolError("'name' parameter is required")
        key = self._decrypted_keys.get(name)
        if key is None:
            raise KeyNotFoundError(f"Key '{name}' not found")
        logger.info("get_key requested: name=%s", name)
        return {
            "name": key.name,
            "key_type": key.key_type,
            "key": base64.b64encode(bytes(key.private_key)).decode(),
            "address": key.address,
        }

    def _handle_get_address(self, params: dict) -> dict:
        chain = params.get("chain", "")
        signer = self._get_chain_signer(chain)
        return {"address": signer.get_address()}

    def _handle_sign_transaction(self, params: dict) -> dict:
        self._check_rate_limit()
        chain = params.get("chain", "")
        signer = self._get_chain_signer(chain)
        return signer.sign_transaction(params.get("tx", {}))

    def _handle_sign_message(self, params: dict) -> dict:
        self._check_rate_limit()
        chain = params.get("chain", "")
        signer = self._get_chain_signer(chain)
        return signer.sign_message(params.get("message", ""))

    def _handle_sign_typed_data(self, params: dict) -> dict:
        self._check_rate_limit()
        chain = params.get("chain", "")
        if chain != "evm":
            raise UnsupportedChainError("sign_typed_data is EVM only")
        signer = self._get_chain_signer(chain)
        return signer.sign_typed_data(
            params.get("domain", {}),
            params.get("types", {}),
            params.get("value", {}),
        )

    def serve(self) -> None:
        """Start serving on Unix domain socket or TCP localhost."""
        if _HAS_AF_UNIX:
            self._serve_unix()
        else:
            self._serve_tcp()

    def _serve_unix(self) -> None:
        """Serve on a Unix domain socket."""
        sock_path = self.config.socket_path
        if os.path.exists(sock_path):
            os.unlink(sock_path)

        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.bind(sock_path)
        set_file_owner_only(sock_path)
        self._socket.listen(5)
        self._socket.settimeout(1.0)
        self._running = True

        logger.info("Signer server listening on %s", sock_path)
        self._accept_loop()

        # Cleanup socket file
        if os.path.exists(sock_path):
            os.unlink(sock_path)

    def _serve_tcp(self) -> None:
        """Serve on TCP localhost (Windows fallback) with token auth."""
        self._tcp_mode = True

        # Generate auth token
        self._tcp_token = os.urandom(32).hex()
        with open(self.config.token_path, "w") as f:
            f.write(self._tcp_token)
        set_file_owner_only(self.config.token_path)

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socket.bind(("127.0.0.1", 0))
        self.server_address = self._socket.getsockname()

        # Write port file so clients can discover us
        with open(self.config.port_path, "w") as f:
            f.write(str(self.server_address[1]))
        set_file_owner_only(self.config.port_path)

        self._socket.listen(5)
        self._socket.settimeout(1.0)
        self._running = True

        logger.info("Signer server listening on %s:%d", *self.server_address)
        self._accept_loop()

    def _accept_loop(self) -> None:
        """Main accept loop shared by Unix and TCP transports."""
        while self._running:
            try:
                conn, _ = self._socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            try:
                conn.settimeout(5.0)
                data = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                    if len(data) > self.config.max_request_size:
                        break
                    if b"\n" in data:
                        break

                if data:
                    response = self._handle_request(data)
                    conn.sendall(response)
            except Exception as e:
                logger.error("Error handling connection: %s", e)
            finally:
                conn.close()

        self._cleanup()

    def shutdown(self) -> None:
        self._running = False
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass

    def _cleanup(self) -> None:
        self.lock()
        if self._tcp_mode:
            for path in (self.config.port_path, self.config.token_path):
                try:
                    os.unlink(path)
                except OSError:
                    pass
        try:
            self._sm.transition_to(SignerState.STOPPED)
        except SignerStateError:
            pass
