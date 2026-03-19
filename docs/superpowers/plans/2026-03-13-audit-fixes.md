# VaultSign Audit Fixes Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 6 issues found during code audit: broken Windows/TCP fallback with no auth, corrupted keystore raw exceptions, client bad response handling, Windows daemon port discovery, change-password double zeroize, and _derive_from_mnemonic missing return.

**Architecture:** Fixes are ordered by dependency — keystore validation and client response parsing are independent leaves, then Windows/TCP transport (the largest change) touches server, client, config, and CLI. Minor fixes are last. Each task produces a working, testable commit.

**Tech Stack:** Python 3.11+, pytest, socket, json, os.urandom for token generation.

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `src/vaultsign/keystore.py` | Modify L238-263 | Wrap field access in `Keystore.load()` with try/except → `WalletFormatError` |
| `src/vaultsign/client.py` | Modify L86-113 | Wrap `json.loads` with error boundary; add TCP fallback from port/token files; include token in TCP requests |
| `src/vaultsign/config.py` | Modify | Add `port_path` and `token_path` properties |
| `src/vaultsign/server.py` | Modify L282-293, L336-341 | Write port/token files in TCP mode; validate token; clean up on shutdown |
| `src/vaultsign/cli.py` | Modify L147-177, L370-384 | Fix double zeroize; add explicit error for unsupported mnemonic type |
| `tests/test_keystore.py` | Modify | Add tests for corrupted keystore files |
| `tests/test_client.py` | Modify | Add tests for bad server responses and TCP fallback |
| `tests/test_server.py` | Modify | Add tests for TCP token auth |

---

## Chunk 1: Keystore Validation & Client Response Parsing

### Task 1: Corrupted keystore → WalletFormatError (Issue 2)

**Files:**
- Modify: `src/vaultsign/keystore.py:250-262`
- Test: `tests/test_keystore.py`

- [ ] **Step 1: Write failing tests for corrupted keystore**

Add to `tests/test_keystore.py`:

```python
import pytest
from vaultsign.errors import WalletFormatError
from vaultsign.keystore import Keystore


def test_load_keystore_missing_fields(tmp_path):
    """Corrupted keystore with missing fields should raise WalletFormatError."""
    ks_path = tmp_path / "keystore.json"
    ks_path.write_text('{"version": 1, "keys": [{"name": "broken"}]}')
    with pytest.raises(WalletFormatError, match="Invalid key entry"):
        Keystore.load(str(ks_path))


def test_load_keystore_bad_base64(tmp_path):
    """Corrupted keystore with invalid base64 should raise WalletFormatError."""
    import json
    ks_path = tmp_path / "keystore.json"
    ks_path.write_text(json.dumps({
        "version": 1,
        "keys": [{
            "name": "bad",
            "key_type": "secp256k1",
            "address": "0x1234",
            "salt": "not-valid-base64!!!",
            "iv": "also-bad",
            "encrypted_key": "nope",
            "tag": "nah",
        }]
    }))
    with pytest.raises(WalletFormatError, match="Invalid key entry"):
        Keystore.load(str(ks_path))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_keystore.py::test_load_keystore_missing_fields tests/test_keystore.py::test_load_keystore_bad_base64 -v`
Expected: FAIL — raw `KeyError` / `binascii.Error` instead of `WalletFormatError`.

- [ ] **Step 3: Implement keystore validation**

In `src/vaultsign/keystore.py`, replace the bare field access in `Keystore.load()` (lines 251-262) with:

```python
        ks = cls(path)
        for i, key_data in enumerate(data.get("keys", [])):
            try:
                ks.entries.append(
                    _EncryptedEntry(
                        name=key_data["name"],
                        key_type=key_data["key_type"],
                        address=key_data["address"],
                        salt=base64.b64decode(key_data["salt"]),
                        iv=base64.b64decode(key_data["iv"]),
                        encrypted_key=base64.b64decode(key_data["encrypted_key"]),
                        tag=base64.b64decode(key_data["tag"]),
                    )
                )
            except (KeyError, TypeError, ValueError) as e:
                raise WalletFormatError(
                    f"Invalid key entry at index {i}: {e}"
                ) from e
        return ks
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_keystore.py -v`
Expected: All PASS (including existing tests).

- [ ] **Step 5: Commit**

```bash
git add src/vaultsign/keystore.py tests/test_keystore.py
git commit -m "fix: wrap corrupted keystore errors in WalletFormatError"
```

---

### Task 2: Client bad response → domain error (Issue 3)

**Files:**
- Modify: `src/vaultsign/client.py:108`
- Test: `tests/test_client.py`

- [ ] **Step 1: Write failing tests for bad responses**

Add to `tests/test_client.py`:

```python
from vaultsign.errors import IPCProtocolError


def test_non_json_response_raises_protocol_error(tmp_path):
    """Non-JSON response from server should raise IPCProtocolError, not JSONDecodeError."""
    import threading

    sock_path = str(tmp_path / "bad.sock")

    def bad_server():
        if _HAS_AF_UNIX:
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(sock_path)
        else:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            bad_server.address = srv.getsockname()
        srv.listen(1)
        conn, _ = srv.accept()
        conn.recv(4096)
        conn.sendall(b"not-json\n")
        conn.close()
        srv.close()

    bad_server.address = None
    t = threading.Thread(target=bad_server, daemon=True)
    t.start()

    if _HAS_AF_UNIX:
        import time
        for _ in range(50):
            if os.path.exists(sock_path):
                break
            time.sleep(0.05)
        client = SignerClient(socket_path=sock_path)
    else:
        import time
        time.sleep(0.2)
        client = SignerClient(host=bad_server.address[0], port=bad_server.address[1])

    with pytest.raises(IPCProtocolError):
        client.ping()


def test_empty_response_raises_protocol_error(tmp_path):
    """Empty response (server closes connection) should raise IPCProtocolError."""
    import threading

    sock_path = str(tmp_path / "empty.sock")

    def empty_server():
        if _HAS_AF_UNIX:
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(sock_path)
        else:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            empty_server.address = srv.getsockname()
        srv.listen(1)
        conn, _ = srv.accept()
        conn.recv(4096)
        conn.close()  # close immediately, no response
        srv.close()

    empty_server.address = None
    t = threading.Thread(target=empty_server, daemon=True)
    t.start()

    if _HAS_AF_UNIX:
        import time
        for _ in range(50):
            if os.path.exists(sock_path):
                break
            time.sleep(0.05)
        client = SignerClient(socket_path=sock_path)
    else:
        import time
        time.sleep(0.2)
        client = SignerClient(host=empty_server.address[0], port=empty_server.address[1])

    with pytest.raises(IPCProtocolError):
        client.ping()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_client.py::test_non_json_response_raises_protocol_error tests/test_client.py::test_empty_response_raises_protocol_error -v`
Expected: FAIL — raw `JSONDecodeError` instead of `IPCProtocolError`.

- [ ] **Step 3: Implement response error boundary**

In `src/vaultsign/client.py`, add `IPCProtocolError` to imports:

```python
from .errors import SignerError, SignerConnectionError, IPCProtocolError
```

Replace the bare `json.loads` at line 108 with:

```python
        if not data:
            raise IPCProtocolError("Empty response from signer")

        try:
            response = json.loads(data.decode().strip())
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise IPCProtocolError(f"Invalid response from signer: {e}") from e
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_client.py -v`
Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add src/vaultsign/client.py tests/test_client.py
git commit -m "fix: wrap bad server responses in IPCProtocolError"
```

---

## Chunk 2: Windows/TCP Transport Fix

### Task 3: Config — add port_path and token_path (Issue 1+4)

**Files:**
- Modify: `src/vaultsign/config.py`

- [ ] **Step 1: Add properties to Config**

In `src/vaultsign/config.py`, add after `pid_path`:

```python
    @property
    def port_path(self) -> str:
        return str(Path(self.home_dir) / "signer.port")

    @property
    def token_path(self) -> str:
        return str(Path(self.home_dir) / "signer.token")
```

- [ ] **Step 2: Verify existing config tests pass**

Run: `pytest tests/test_config.py -v`
Expected: All PASS.

- [ ] **Step 3: Commit**

```bash
git add src/vaultsign/config.py
git commit -m "feat: add port_path and token_path to Config"
```

---

### Task 4: Server — TCP token auth + port/token file management (Issue 1+4)

**Files:**
- Modify: `src/vaultsign/server.py:282-293, 336-341, 139-162`
- Test: `tests/test_server.py`

- [ ] **Step 1: Write failing test for TCP token auth**

Add to `tests/test_server.py`:

```python
def test_tcp_token_auth(server_env):
    """TCP mode requires a valid token; requests without it are rejected."""
    config, ks_path, sock_path = server_env
    server = SignerServer(config)
    server.load_keystore()

    # Force TCP mode
    import vaultsign.server as server_mod
    original = server_mod._HAS_AF_UNIX
    server_mod._HAS_AF_UNIX = False
    try:
        t = threading.Thread(target=server.serve, daemon=True)
        t.start()
        for _ in range(50):
            if server.server_address is not None:
                break
            time.sleep(0.05)
        address = server.server_address

        # Request WITHOUT token should be rejected
        resp = _send_request(address, {
            "version": 1, "id": "t1", "method": "ping", "params": {}
        })
        assert "error" in resp
        assert resp["error"]["code"] == 1009  # PermissionDeniedError

        # Request WITH correct token should succeed
        token = open(config.token_path).read().strip()
        resp = _send_request(address, {
            "version": 1, "id": "t2", "method": "ping", "params": {},
            "token": token,
        })
        assert "result" in resp
        assert resp["result"]["status"] == "ok"
    finally:
        server.shutdown()
        server_mod._HAS_AF_UNIX = original
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_server.py::test_tcp_token_auth -v`
Expected: FAIL — no token validation exists.

- [ ] **Step 3: Implement TCP token auth and port/token file management**

In `src/vaultsign/server.py`:

Add import at top:

```python
from .errors import (
    ...
    PermissionDeniedError,
)
```

Add `self._tcp_token` and `self._tcp_mode` to `__init__`:

```python
        self._tcp_mode = False
        self._tcp_token: str | None = None
```

Replace `_serve_tcp` method:

```python
    def _serve_tcp(self) -> None:
        """Serve on TCP localhost (Windows fallback) with token auth."""
        from .security.platform import set_file_owner_only

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
```

Add token validation in `_handle_request`, after version check (after line 153):

```python
        # TCP token auth
        if self._tcp_mode:
            token = request.get("token")
            if token != self._tcp_token:
                err = PermissionDeniedError("Invalid or missing auth token")
                return (json.dumps({"id": req_id, "error": err.to_dict()}) + "\n").encode()
```

Update `_cleanup` to remove port/token files:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_server.py -v`
Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add src/vaultsign/server.py
git commit -m "feat: add TCP token auth and port/token file management"
```

---

### Task 5: Client — TCP fallback from port/token files (Issue 1)

**Files:**
- Modify: `src/vaultsign/client.py:49-66, 86-92`
- Test: `tests/test_client.py`

- [ ] **Step 1: Write failing test for TCP fallback**

Add to `tests/test_client.py`:

```python
def test_tcp_fallback_reads_port_and_token(tmp_path, mock_server):
    """When socket_path is set but AF_UNIX unavailable, client reads port/token files."""
    import vaultsign.client as client_mod
    original = client_mod._HAS_AF_UNIX

    address, set_response = mock_server
    set_response("ping", {"status": "ok"})

    # This test is meaningful only when we can simulate no-AF_UNIX with a TCP mock
    if not isinstance(address, tuple):
        pytest.skip("Mock server is Unix-mode; need TCP for this test")

    host, port = address
    sock_dir = tmp_path / "fake-home"
    sock_dir.mkdir()
    sock_path = str(sock_dir / "signer.sock")

    # Write port and token files
    (sock_dir / "signer.port").write_text(str(port))
    (sock_dir / "signer.token").write_text("test-token-ignored-by-mock")

    client_mod._HAS_AF_UNIX = False
    try:
        client = SignerClient(socket_path=sock_path)
        result = client.ping()
        assert result["status"] == "ok"
    finally:
        client_mod._HAS_AF_UNIX = original
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_client.py::test_tcp_fallback_reads_port_and_token -v`
Expected: FAIL — client tries to connect with (None, None).

- [ ] **Step 3: Implement TCP fallback in client**

In `src/vaultsign/client.py`, update `__init__`:

```python
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
            if _HAS_AF_UNIX:
                self._socket_path = _default_socket_path()
            else:
                self._host = "127.0.0.1"
                self._port = 9473

        self.evm = _ChainClient(self._send, "evm")
        self.solana = _ChainClient(self._send, "solana")

    def _resolve_tcp_from_socket_path(self, socket_path: str) -> None:
        """On Windows, read port/token files from the socket_path's directory."""
        from pathlib import Path
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
```

Update `_send` to include token when set:

```python
    def _send(self, method: str, params: dict | None = None) -> dict:
        request = {
            "version": 1,
            "id": str(uuid.uuid4())[:8],
            "method": method,
            "params": params or {},
        }
        if self._token:
            request["token"] = self._token
        ...
```

- [ ] **Step 4: Run all client tests**

Run: `pytest tests/test_client.py -v`
Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add src/vaultsign/client.py tests/test_client.py
git commit -m "feat: client reads port/token files for Windows TCP fallback"
```

---

## Chunk 3: Minor Fixes

### Task 6: Fix change-password double zeroize (Issue 5)

**Files:**
- Modify: `src/vaultsign/cli.py:370-384`

- [ ] **Step 1: Fix the double zeroize**

In `src/vaultsign/cli.py`, replace the change_password error handling (lines 378-384):

```python
    try:
        keys = ks.decrypt_all(old_pass)
    except Exception as e:
        raise click.ClickException(f"Wrong password: {e}")
    finally:
        zeroize(old_pass)
```

This removes the redundant `zeroize(old_pass)` from the `except` block — the `finally` block handles it in all cases.

- [ ] **Step 2: Commit**

```bash
git add src/vaultsign/cli.py
git commit -m "fix: remove redundant zeroize in change-password"
```

---

### Task 7: Fix _derive_from_mnemonic missing return (Issue 6)

**Files:**
- Modify: `src/vaultsign/cli.py:147-177`

- [ ] **Step 1: Add explicit error for unsupported type**

In `src/vaultsign/cli.py`, add at the end of `_derive_from_mnemonic`, after the `elif` block but before the `except`:

```python
    else:
        raise click.ClickException(f"Unsupported key type for mnemonic: {key_type}")
```

The full function becomes:

```python
def _derive_from_mnemonic(mnemonic: str, key_type: str) -> bytearray:
    try:
        if key_type == "evm":
            from eth_account import Account
            Account.enable_unaudited_hdwallet_features()
            acct = Account.from_mnemonic(mnemonic, account_path="m/44'/60'/0'/0/0")
            return bytearray(acct.key)
        elif key_type == "solana":
            from bip_utils import (
                Bip39SeedGenerator,
                Bip44,
                Bip44Coins,
                Bip44Changes,
            )
            seed = Bip39SeedGenerator(mnemonic).Generate()
            bip44_ctx = (
                Bip44.FromSeed(seed, Bip44Coins.SOLANA)
                .Purpose()
                .Coin()
                .Account(0)
                .Change(Bip44Changes.CHAIN_EXT)
            )
            private_key_bytes = bip44_ctx.PrivateKey().Raw().ToBytes()
            return bytearray(private_key_bytes)
        else:
            raise click.ClickException(f"Unsupported key type for mnemonic: {key_type}")
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(f"Mnemonic derivation failed: {e}")
```

- [ ] **Step 2: Commit**

```bash
git add src/vaultsign/cli.py
git commit -m "fix: add explicit error for unsupported mnemonic key type"
```

---

## Summary of Changes

| Issue | Severity | Files Modified | Test Coverage |
|-------|----------|---------------|---------------|
| #2 Corrupted keystore | Medium | keystore.py | test_keystore.py: 2 new tests |
| #3 Client bad response | Medium | client.py | test_client.py: 2 new tests |
| #1+#4 Windows/TCP transport | High | config.py, server.py, client.py | test_server.py: 1 new test, test_client.py: 1 new test |
| #5 Double zeroize | Low | cli.py | Existing tests cover |
| #6 Missing return | Low | cli.py | Guarded by click.Choice in practice |
