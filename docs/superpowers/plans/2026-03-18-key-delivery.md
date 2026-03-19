# Key Delivery & Opaque Key Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `get_key` IPC method and `exec` CLI command so business processes can retrieve decrypted keys for use with third-party SDKs, plus support storing arbitrary (opaque) secrets.

**Architecture:** Extends existing daemon with a new IPC handler (`get_key`) that returns decrypted keys by name. Keystore gains `opaque` key type with auto-detection on import. CLI `exec` command wraps `get_key` to inject keys as environment variables into child processes.

**Tech Stack:** Python, click (CLI), argon2-cffi, cryptography (AES-256-GCM), eth-account (EVM address derivation), pytest

---

### Task 1: Add `KeyNotFoundError` to error model

**Files:**
- Modify: `src/vaultsign/errors.py`
- Modify: `src/vaultsign/__init__.py`
- Test: `tests/test_errors.py`

- [ ] **Step 1: Write the failing test**

In `tests/test_errors.py`, add:

```python
def test_key_not_found_error_code():
    from vaultsign.errors import KeyNotFoundError, ErrorCode
    err = KeyNotFoundError("key 'foo' not found")
    assert err.code == ErrorCode.KEY_NOT_FOUND
    assert err.code.value == 1010
    d = err.to_dict()
    assert d["code"] == 1010
    assert "foo" in d["message"]


def test_key_not_found_error_roundtrip():
    from vaultsign.errors import KeyNotFoundError, SignerError
    err = KeyNotFoundError("not found")
    d = err.to_dict()
    restored = SignerError.from_dict(d)
    assert isinstance(restored, KeyNotFoundError)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_errors.py::test_key_not_found_error_code tests/test_errors.py::test_key_not_found_error_roundtrip -v`
Expected: FAIL with `ImportError: cannot import name 'KeyNotFoundError'`

- [ ] **Step 3: Write minimal implementation**

In `src/vaultsign/errors.py`, add to `ErrorCode` enum:

```python
KEY_NOT_FOUND = 1010
```

Add new error class after `PermissionDeniedError`:

```python
class KeyNotFoundError(SignerError):
    code = ErrorCode.KEY_NOT_FOUND
```

In `src/vaultsign/__init__.py`, add `KeyNotFoundError` to imports and `__all__`.

- [ ] **Step 4: Run test to verify it passes**

Run: `uv run pytest tests/test_errors.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/vaultsign/errors.py src/vaultsign/__init__.py tests/test_errors.py
git commit -m "feat: add KeyNotFoundError (code 1010) to error model"
```

---

### Task 2: Support opaque keys in keystore — data model & add/decrypt

**Files:**
- Modify: `src/vaultsign/keystore.py`
- Test: `tests/test_keystore.py`

- [ ] **Step 1: Write failing tests for opaque key storage**

In `tests/test_keystore.py`, add:

```python
def test_add_opaque_key(tmp_path):
    """Opaque keys can be stored with address=None."""
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="lighter-api",
        key_type="opaque",
        address=None,
        private_key=bytearray(b"some-api-key-string"),
        password=bytearray(b"testpassword123"),
    )
    ks.save()

    data = json.loads(ks_path.read_text())
    assert len(data["keys"]) == 1
    assert data["keys"][0]["name"] == "lighter-api"
    assert data["keys"][0]["key_type"] == "opaque"
    assert data["keys"][0]["address"] is None


def test_decrypt_opaque_key(tmp_path):
    """Opaque keys can be decrypted and return original bytes."""
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    original = b"my-secret-lighter-api-key-12345"
    ks.add_key(
        name="lighter-api",
        key_type="opaque",
        address=None,
        private_key=bytearray(original),
        password=bytearray(b"testpassword123"),
    )
    ks.save()

    ks2 = Keystore.load(str(ks_path))
    decrypted = ks2.decrypt_all(bytearray(b"testpassword123"))
    assert len(decrypted) == 1
    assert decrypted[0].key_type == "opaque"
    assert decrypted[0].address is None
    assert bytes(decrypted[0].private_key) == original


def test_multiple_opaque_keys_allowed(tmp_path):
    """Multiple opaque keys with different names are allowed."""
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="lighter-main",
        key_type="opaque",
        address=None,
        private_key=bytearray(b"key1"),
        password=bytearray(b"testpassword123"),
    )
    ks.add_key(
        name="lighter-sub",
        key_type="opaque",
        address=None,
        private_key=bytearray(b"key2"),
        password=bytearray(b"testpassword123"),
    )
    assert len(ks.entries) == 2


def test_duplicate_name_rejected(tmp_path):
    """Adding a key with a duplicate name raises ValueError."""
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="my-key",
        key_type="opaque",
        address=None,
        private_key=bytearray(b"key1"),
        password=bytearray(b"testpassword123"),
    )
    with pytest.raises(ValueError, match="name.*already exists"):
        ks.add_key(
            name="my-key",
            key_type="opaque",
            address=None,
            private_key=bytearray(b"key2"),
            password=bytearray(b"testpassword123"),
        )


def test_opaque_and_evm_coexist(tmp_path):
    """Opaque and secp256k1 keys can coexist in the same keystore."""
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="my-evm",
        key_type="secp256k1",
        address="0xabc",
        private_key=bytearray(b"\x01" * 32),
        password=bytearray(b"testpassword123"),
    )
    ks.add_key(
        name="lighter-api",
        key_type="opaque",
        address=None,
        private_key=bytearray(b"lighter-secret"),
        password=bytearray(b"testpassword123"),
    )
    ks.save()

    ks2 = Keystore.load(str(ks_path))
    decrypted = ks2.decrypt_all(bytearray(b"testpassword123"))
    assert len(decrypted) == 2
    types = {d.key_type for d in decrypted}
    assert types == {"secp256k1", "opaque"}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_keystore.py::test_add_opaque_key tests/test_keystore.py::test_decrypt_opaque_key tests/test_keystore.py::test_multiple_opaque_keys_allowed tests/test_keystore.py::test_duplicate_name_rejected tests/test_keystore.py::test_opaque_and_evm_coexist -v`
Expected: FAIL — `address` type mismatch, one-per-chain check blocks opaque, no name uniqueness check

- [ ] **Step 3: Implement keystore changes**

In `src/vaultsign/keystore.py`:

**3a.** Change `address` field type in both dataclasses:

```python
@dataclass
class KeyEntry:
    name: str
    key_type: str
    address: str | None
    private_key: bytearray | None = None

    def __repr__(self) -> str:
        pk_repr = f"bytearray(len={len(self.private_key)})" if self.private_key else "None"
        return f"KeyEntry(name={self.name!r}, key_type={self.key_type!r}, address={self.address!r}, private_key={pk_repr})"


@dataclass
class _EncryptedEntry:
    name: str
    key_type: str
    address: str | None
    salt: bytes
    iv: bytes
    encrypted_key: bytes
    tag: bytes
```

**3b.** Replace the `add_key` validation logic to add name uniqueness and exempt opaque from one-per-chain:

```python
def add_key(
    self,
    name: str,
    key_type: str,
    address: str | None,
    private_key: bytearray,
    password: bytearray,
) -> None:
    """Encrypt and add a key to the keystore."""
    # Name uniqueness check
    for entry in self.entries:
        if entry.name == name:
            raise ValueError(
                f"A key with name '{name}' already exists."
            )

    # v1: one key per chain type (opaque exempt)
    if key_type != "opaque":
        chain_types = {"secp256k1": "evm"}
        chain = chain_types.get(key_type, key_type)
        for entry in self.entries:
            if entry.key_type == "opaque":
                continue
            entry_chain = chain_types.get(entry.key_type, entry.key_type)
            if entry_chain == chain:
                raise ValueError(
                    f"A key for chain type '{chain}' already exists. "
                    "v1 supports one key per chain type."
                )

    salt, iv, ct, tag = _encrypt(private_key, password)
    zeroize(private_key)

    self.entries.append(
        _EncryptedEntry(
            name=name,
            key_type=key_type,
            address=address,
            salt=salt,
            iv=iv,
            encrypted_key=ct,
            tag=tag,
        )
    )
```

**3c.** In `decrypt_all`, guard the address comparison against `None`:

```python
# Verify address matches (spec requirement)
derived_addr = _derive_address_from_key(entry.key_type, pk)
if derived_addr and entry.address and derived_addr.lower() != entry.address.lower():
    zeroize(pk)
    raise WalletFormatError(
        f"Address mismatch for key '{entry.name}': "
        f"expected {entry.address}, derived {derived_addr}. "
        "Keystore may be corrupted."
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_keystore.py -v`
Expected: All PASS (both new and existing tests)

- [ ] **Step 5: Commit**

```bash
git add src/vaultsign/keystore.py tests/test_keystore.py
git commit -m "feat: support opaque key type in keystore with name uniqueness"
```

---

### Task 3: Add name-based key lookup to keystore

**Files:**
- Modify: `src/vaultsign/keystore.py`
- Test: `tests/test_keystore.py`

- [ ] **Step 1: Write failing test**

In `tests/test_keystore.py`, add:

```python
def test_get_decrypted_key_by_name(tmp_path):
    """Can look up a specific decrypted key by name."""
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="my-evm",
        key_type="secp256k1",
        address="0xabc",
        private_key=bytearray(b"\x01" * 32),
        password=bytearray(b"testpassword123"),
    )
    ks.add_key(
        name="lighter-api",
        key_type="opaque",
        address=None,
        private_key=bytearray(b"lighter-secret"),
        password=bytearray(b"testpassword123"),
    )
    ks.save()

    ks2 = Keystore.load(str(ks_path))
    decrypted = ks2.decrypt_all(bytearray(b"testpassword123"))

    result = Keystore.find_by_name(decrypted, "lighter-api")
    assert result is not None
    assert result.name == "lighter-api"
    assert bytes(result.private_key) == b"lighter-secret"

    result2 = Keystore.find_by_name(decrypted, "nonexistent")
    assert result2 is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_keystore.py::test_get_decrypted_key_by_name -v`
Expected: FAIL with `AttributeError: type object 'Keystore' has no attribute 'find_by_name'`

- [ ] **Step 3: Implement `find_by_name`**

In `src/vaultsign/keystore.py`, add static method to `Keystore`:

```python
@staticmethod
def find_by_name(keys: list[KeyEntry], name: str) -> KeyEntry | None:
    """Find a decrypted key by name. Returns None if not found."""
    for key in keys:
        if key.name == name:
            return key
    return None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_keystore.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/vaultsign/keystore.py tests/test_keystore.py
git commit -m "feat: add name-based key lookup to keystore"
```

---

### Task 4: Add `get_key` IPC handler to server

**Files:**
- Modify: `src/vaultsign/server.py`
- Test: `tests/test_server.py`

- [ ] **Step 1: Write failing tests**

In `tests/test_server.py`, add a new fixture that includes an opaque key, and new test functions:

```python
@pytest.fixture
def server_env_with_opaque(tmp_path):
    """Set up a keystore with both EVM and opaque keys."""
    home = tmp_path / ".vaultsign"
    home.mkdir()
    ks_path = home / "keystore.json"
    sock_path = str(home / "signer.sock")

    ks = Keystore(str(ks_path))
    test_key = bytearray(bytes.fromhex(
        "4c0883a69102937d6231471b5dbb6204fe512961708279f15b0d7e4b2cd53f37"
    ))
    ks.add_key(
        name="test-evm",
        key_type="secp256k1",
        address="0x864eC9c7662f55Af9f7637162042d9F5b2aDb1dB",
        private_key=test_key,
        password=bytearray(b"testpass1234"),
    )
    ks.add_key(
        name="lighter-api",
        key_type="opaque",
        address=None,
        private_key=bytearray(b"my-lighter-secret-key"),
        password=bytearray(b"testpass1234"),
    )
    ks.save()

    config = Config(
        home_dir=str(home),
        socket_path=sock_path,
        rate_limit=1000,
    )
    return config, str(ks_path), sock_path


@pytest.fixture
def running_server_with_opaque(server_env_with_opaque):
    config, ks_path, sock_path = server_env_with_opaque
    server = SignerServer(config)
    server.load_keystore()

    t = threading.Thread(target=server.serve, daemon=True)
    t.start()

    token = None
    if hasattr(socket, "AF_UNIX"):
        for _ in range(50):
            if os.path.exists(sock_path):
                break
            time.sleep(0.05)
        address = sock_path
    else:
        for _ in range(50):
            if server.server_address is not None:
                break
            time.sleep(0.05)
        address = server.server_address
        token = server._tcp_token

    yield server, address, token

    server.shutdown()


def test_get_key_opaque(running_server_with_opaque):
    """get_key returns decrypted opaque key by name."""
    server, address, token = running_server_with_opaque
    # Unlock first
    _send_request(address, {
        "version": 1, "id": "u1", "method": "unlock",
        "params": {"password": "testpass1234"}
    }, token=token)

    resp = _send_request(address, {
        "version": 1, "id": "gk1", "method": "get_key",
        "params": {"name": "lighter-api"}
    }, token=token)
    assert "result" in resp
    assert resp["result"]["name"] == "lighter-api"
    assert resp["result"]["key_type"] == "opaque"
    assert resp["result"]["address"] is None
    # Decode base64 key and verify content
    import base64
    key_bytes = base64.b64decode(resp["result"]["key"])
    assert key_bytes == b"my-lighter-secret-key"


def test_get_key_evm(running_server_with_opaque):
    """get_key also works for secp256k1 keys."""
    server, address, token = running_server_with_opaque
    _send_request(address, {
        "version": 1, "id": "u2", "method": "unlock",
        "params": {"password": "testpass1234"}
    }, token=token)

    resp = _send_request(address, {
        "version": 1, "id": "gk2", "method": "get_key",
        "params": {"name": "test-evm"}
    }, token=token)
    assert "result" in resp
    assert resp["result"]["name"] == "test-evm"
    assert resp["result"]["key_type"] == "secp256k1"
    assert resp["result"]["address"] is not None


def test_get_key_not_found(running_server_with_opaque):
    """get_key returns KeyNotFoundError for unknown names."""
    server, address, token = running_server_with_opaque
    _send_request(address, {
        "version": 1, "id": "u3", "method": "unlock",
        "params": {"password": "testpass1234"}
    }, token=token)

    resp = _send_request(address, {
        "version": 1, "id": "gk3", "method": "get_key",
        "params": {"name": "nonexistent"}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1010


def test_get_key_when_locked(running_server_with_opaque):
    """get_key returns SignerLockedError when locked."""
    server, address, token = running_server_with_opaque
    resp = _send_request(address, {
        "version": 1, "id": "gk4", "method": "get_key",
        "params": {"name": "lighter-api"}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1001


def test_get_key_missing_name(running_server_with_opaque):
    """get_key with empty name returns IPCProtocolError."""
    server, address, token = running_server_with_opaque
    _send_request(address, {
        "version": 1, "id": "u5", "method": "unlock",
        "params": {"password": "testpass1234"}
    }, token=token)

    resp = _send_request(address, {
        "version": 1, "id": "gk5", "method": "get_key",
        "params": {}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008  # IPCProtocolError
```

Also add a rate-limit-specific fixture and test:

```python
@pytest.fixture
def server_env_low_rate_limit(tmp_path):
    """Server with rate_limit=2 for testing rate limiting."""
    home = tmp_path / ".vaultsign"
    home.mkdir()
    ks_path = home / "keystore.json"
    sock_path = str(home / "signer.sock")

    ks = Keystore(str(ks_path))
    ks.add_key(
        name="test-key",
        key_type="opaque",
        address=None,
        private_key=bytearray(b"secret"),
        password=bytearray(b"testpass1234"),
    )
    ks.save()

    config = Config(
        home_dir=str(home),
        socket_path=sock_path,
        rate_limit=2,  # very low limit
    )
    return config, str(ks_path), sock_path


def test_get_key_rate_limited(server_env_low_rate_limit):
    """get_key is subject to rate limiting."""
    config, ks_path, sock_path = server_env_low_rate_limit
    server = SignerServer(config)
    server.load_keystore()

    t = threading.Thread(target=server.serve, daemon=True)
    t.start()

    token = None
    if hasattr(socket, "AF_UNIX"):
        for _ in range(50):
            if os.path.exists(sock_path):
                break
            time.sleep(0.05)
        address = sock_path
    else:
        for _ in range(50):
            if server.server_address is not None:
                break
            time.sleep(0.05)
        address = server.server_address
        token = server._tcp_token

    try:
        # Unlock
        _send_request(address, {
            "version": 1, "id": "u", "method": "unlock",
            "params": {"password": "testpass1234"}
        }, token=token)

        # First 2 calls should succeed (rate_limit=2)
        for i in range(2):
            resp = _send_request(address, {
                "version": 1, "id": f"rl{i}", "method": "get_key",
                "params": {"name": "test-key"}
            }, token=token)
            assert "result" in resp

        # Third call should be rate limited
        resp = _send_request(address, {
            "version": 1, "id": "rl3", "method": "get_key",
            "params": {"name": "test-key"}
        }, token=token)
        assert "error" in resp
        assert resp["error"]["code"] == 1006  # PolicyViolationError
    finally:
        server.shutdown()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_server.py::test_get_key_opaque tests/test_server.py::test_get_key_not_found tests/test_server.py::test_get_key_when_locked tests/test_server.py::test_get_key_evm -v`
Expected: FAIL — `get_key` method not in dispatch table

- [ ] **Step 3: Implement server changes**

In `src/vaultsign/server.py`:

**3a.** Add import at top:

```python
from .errors import (
    ...existing imports...,
    KeyNotFoundError,
)
```

**3b.** Add `import base64` at the top of `server.py` (module-level, next to other imports). Also add storage for decrypted keys in `SignerServer.__init__` — this MUST be done before any other changes since `lock()` accesses it:

```python
self._decrypted_keys: dict[str, KeyEntry] = {}
```

`KeyEntry` is already imported from `.keystore` — verify the existing import line includes it.

**3c.** In the `unlock` method, after the loop that creates `self._evm`, also populate `_decrypted_keys`:

```python
for key in keys:
    if self.config.try_mlock and key.private_key:
        lock_key_memory(key.private_key)

    if key.key_type == "secp256k1":
        self._evm = EVMSigner(key.private_key)

    # Store all keys by name for get_key
    self._decrypted_keys[key.name] = key
```

**3d.** In the `lock` method, zeroize and clear the decrypted keys:

```python
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
```

**3e.** Add the handler method (note: `base64` was imported at module level in Step 3b):

```python
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
```

**3f.** Register in `_dispatch`:

```python
def _dispatch(self, method: str, params: dict) -> dict:
    handlers = {
        ...existing handlers...,
        "get_key": self._handle_get_key,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_server.py -v`
Expected: All PASS (both new and existing tests)

- [ ] **Step 5: Commit**

```bash
git add src/vaultsign/server.py tests/test_server.py
git commit -m "feat: add get_key IPC handler for key delivery by name"
```

---

### Task 5: Add `get_key` to client library

**Files:**
- Modify: `src/vaultsign/client.py`
- Test: `tests/test_client.py`

- [ ] **Step 1: Write failing test**

In `tests/test_client.py`, add (check existing test patterns first — client tests may mock IPC):

```python
import base64
import json
from unittest.mock import patch, MagicMock
from vaultsign.client import SignerClient


def test_get_key_returns_decoded_string():
    """get_key decodes the base64 key from IPC response."""
    original_key = "my-lighter-secret-key"
    mock_result = {
        "name": "lighter-api",
        "key_type": "opaque",
        "key": base64.b64encode(original_key.encode("utf-8")).decode(),
        "address": None,
    }

    client = SignerClient(host="127.0.0.1", port=9999)
    with patch.object(client, "_send", return_value=mock_result) as mock_send:
        result = client.get_key("lighter-api")

    assert result == original_key
    mock_send.assert_called_once_with("get_key", {"name": "lighter-api"})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_client.py::test_get_key_returns_decoded_string -v`
Expected: FAIL with `AttributeError: 'SignerClient' object has no attribute 'get_key'`

- [ ] **Step 3: Implement client `get_key`**

In `src/vaultsign/client.py`, add `import base64` at the module level (top of file, next to other imports). Then add method to `SignerClient`:

```python
def get_key(self, name: str) -> str:
    """Retrieve a decrypted key by name.

    Returns the key as a string (the original value stored during add).
    """
    result = self._send("get_key", {"name": name})
    key_b64 = result["key"]
    return base64.b64decode(key_b64).decode("utf-8")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_client.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/vaultsign/client.py tests/test_client.py
git commit -m "feat: add get_key method to SignerClient"
```

---

### Task 6: Update CLI `add` command — auto-detect key type

**Files:**
- Modify: `src/vaultsign/cli.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write failing tests**

In `tests/test_cli.py`, add:

```python
def test_add_key_auto_detect_evm(runner, tmp_path):
    """add --key without --type auto-detects secp256k1."""
    home = str(tmp_path / ".vaultsign")
    (tmp_path / ".vaultsign").mkdir()
    ks_path = tmp_path / ".vaultsign" / "keystore.json"
    ks_path.write_text(json.dumps({"version": 1, "kdf": "argon2id", "kdf_params": {}, "keys": []}))

    test_key = "4c0883a69102937d6231471b5dbb6204fe512961708279f15b0d7e4b2cd53f37"
    input_text = f"{test_key}\ntestpass1234\ntestpass1234\n"

    result = runner.invoke(
        main,
        ["add", "--name", "auto-evm", "--key", "--home", home],
        input=input_text,
    )
    assert result.exit_code == 0, f"CLI output: {result.output}"

    data = json.loads(ks_path.read_text())
    assert data["keys"][0]["key_type"] == "secp256k1"
    assert data["keys"][0]["address"] is not None


def test_add_key_auto_detect_opaque(runner, tmp_path):
    """add --key without --type falls back to opaque for non-EVM keys."""
    home = str(tmp_path / ".vaultsign")
    (tmp_path / ".vaultsign").mkdir()
    ks_path = tmp_path / ".vaultsign" / "keystore.json"
    ks_path.write_text(json.dumps({"version": 1, "kdf": "argon2id", "kdf_params": {}, "keys": []}))

    # Not a valid hex private key — should fall back to opaque
    input_text = "this-is-a-lighter-api-key-not-hex\ntestpass1234\ntestpass1234\n"

    result = runner.invoke(
        main,
        ["add", "--name", "lighter-api", "--key", "--home", home],
        input=input_text,
    )
    assert result.exit_code == 0, f"CLI output: {result.output}"
    assert "opaque" in result.output.lower() or "Cannot derive" in result.output

    data = json.loads(ks_path.read_text())
    assert data["keys"][0]["key_type"] == "opaque"
    assert data["keys"][0]["address"] is None


def test_add_key_explicit_opaque(runner, tmp_path):
    """add --type opaque skips auto-detection."""
    home = str(tmp_path / ".vaultsign")
    (tmp_path / ".vaultsign").mkdir()
    ks_path = tmp_path / ".vaultsign" / "keystore.json"
    ks_path.write_text(json.dumps({"version": 1, "kdf": "argon2id", "kdf_params": {}, "keys": []}))

    # Even a valid hex key should be stored as opaque when --type opaque
    test_key = "4c0883a69102937d6231471b5dbb6204fe512961708279f15b0d7e4b2cd53f37"
    input_text = f"{test_key}\ntestpass1234\ntestpass1234\n"

    result = runner.invoke(
        main,
        ["add", "--name", "forced-opaque", "--type", "opaque", "--key", "--home", home],
        input=input_text,
    )
    assert result.exit_code == 0, f"CLI output: {result.output}"

    data = json.loads(ks_path.read_text())
    assert data["keys"][0]["key_type"] == "opaque"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cli.py::test_add_key_auto_detect_evm tests/test_cli.py::test_add_key_auto_detect_opaque tests/test_cli.py::test_add_key_explicit_opaque -v`
Expected: FAIL — `--type` is currently required

- [ ] **Step 3: Implement CLI add changes**

In `src/vaultsign/cli.py`:

**3a.** Update the `add` command signature — `--type` becomes optional with `opaque` added:

```python
@main.command()
@click.option("--name", required=True, help="Key name")
@click.option("--type", "key_type", required=False, default=None,
              type=click.Choice(["evm", "opaque"]), help="Key type (auto-detected if omitted)")
@click.option("--key", "import_key", is_flag=True, help="Import private key")
@click.option("--mnemonic", "import_mnemonic", is_flag=True, help="Import from mnemonic")
@click.option("--home", default=None, help="Override home directory")
def add(name, key_type, import_key, import_mnemonic, home):
```

**3b.** Replace the body of `add` with auto-detection logic:

```python
def add(name, key_type, import_key, import_mnemonic, home):
    """Add a key to the keystore."""
    if not import_key and not import_mnemonic:
        raise click.ClickException("Specify --key or --mnemonic")

    if import_mnemonic and key_type == "opaque":
        raise click.ClickException("Mnemonic import is not supported for opaque keys")

    config = _get_config(home)
    ks = _get_or_create_keystore(config)

    if import_mnemonic:
        # Mnemonic always produces EVM key
        mnemonic = click.prompt("Enter mnemonic phrase", hide_input=True)
        raw_bytes = _derive_from_mnemonic(mnemonic, key_type or "evm")
        del mnemonic
        internal_type = "secp256k1"
        address = _derive_address("evm", raw_bytes)
    elif key_type == "opaque":
        # Explicit opaque: store raw input as bytes, no address derivation
        raw_input = click.prompt("Enter private key", hide_input=True)
        raw_bytes = bytearray(raw_input.encode("utf-8"))
        del raw_input
        internal_type = "opaque"
        address = None
    elif key_type == "evm":
        # Explicit EVM
        raw_hex = click.prompt("Enter private key", hide_input=True)
        raw_bytes = bytearray(bytes.fromhex(raw_hex.strip().removeprefix("0x")))
        address = _derive_address("evm", raw_bytes)
        internal_type = "secp256k1"
    else:
        # Auto-detect: try EVM first, fall back to opaque
        raw_input = click.prompt("Enter private key", hide_input=True)
        try:
            raw_bytes = bytearray(bytes.fromhex(raw_input.strip().removeprefix("0x")))
            address = _derive_address("evm", raw_bytes)
            internal_type = "secp256k1"
        except Exception:
            raw_bytes = bytearray(raw_input.encode("utf-8"))
            internal_type = "opaque"
            address = None
            click.echo("Warning: Cannot derive address; storing as opaque key.")
        del raw_input

    password_str = click.prompt("Enter password", hide_input=True)
    confirm_str = click.prompt("Confirm password", hide_input=True)

    if password_str != confirm_str:
        zeroize(raw_bytes)
        raise click.ClickException("Passwords do not match")

    if len(password_str) < config.min_password_length:
        zeroize(raw_bytes)
        raise click.ClickException(
            f"Password must be at least {config.min_password_length} characters"
        )

    password = bytearray(password_str.encode("utf-8"))
    del password_str, confirm_str

    try:
        ks.add_key(
            name=name,
            key_type=internal_type,
            address=address,
            private_key=raw_bytes,
            password=password,
        )
        ks.save()
    finally:
        zeroize(password)

    if address:
        click.echo(f"Key '{name}' added. Type: {internal_type}, Address: {address}")
    else:
        click.echo(f"Key '{name}' added. Type: {internal_type}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli.py -v`
Expected: All PASS (both new and existing tests)

- [ ] **Step 5: Commit**

```bash
git add src/vaultsign/cli.py tests/test_cli.py
git commit -m "feat: auto-detect key type on add, support --type opaque"
```

---

### Task 7: Update CLI `list` command for opaque keys

**Files:**
- Modify: `src/vaultsign/cli.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write failing test**

In `tests/test_cli.py`, add:

```python
def test_list_shows_opaque_key(runner, tmp_path):
    """list command shows opaque keys with (none) for address."""
    home = str(tmp_path / ".vaultsign")
    (tmp_path / ".vaultsign").mkdir()
    ks_path = tmp_path / ".vaultsign" / "keystore.json"
    ks_path.write_text(json.dumps({"version": 1, "kdf": "argon2id", "kdf_params": {}, "keys": []}))

    # Add opaque key
    runner.invoke(
        main,
        ["add", "--name", "lighter-api", "--type", "opaque", "--key", "--home", home],
        input="some-api-key\ntestpass1234\ntestpass1234\n",
    )

    result = runner.invoke(main, ["list", "--home", home])
    assert result.exit_code == 0
    assert "lighter-api" in result.output
    assert "opaque" in result.output
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py::test_list_shows_opaque_key -v`
Expected: FAIL — current `list` uses `reverse_type` mapping and doesn't handle opaque/None address

- [ ] **Step 3: Update `list_keys` command**

In `src/vaultsign/cli.py`, replace the `list_keys` function:

```python
@main.command("list")
@click.option("--home", default=None, help="Override home directory")
def list_keys(home):
    """List stored keys."""
    config = _get_config(home)
    try:
        ks = Keystore.load(config.keystore_path)
    except WalletFormatError:
        click.echo("No keystore found. Run 'vaultsign init' first.")
        return

    keys = ks.list_keys()
    if not keys:
        click.echo("No keys stored.")
        return

    reverse_type = {v: k for k, v in _TYPE_MAP.items()}
    for k in keys:
        display_type = reverse_type.get(k["key_type"], k["key_type"])
        display_addr = k["address"] if k["address"] else "(none)"
        click.echo(f"  {k['name']}  [{display_type}]  {display_addr}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/vaultsign/cli.py tests/test_cli.py
git commit -m "feat: update list command to display opaque keys"
```

---

### Task 8: Add `exec` CLI command

**Files:**
- Modify: `src/vaultsign/cli.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write failing test**

In `tests/test_cli.py`, add:

```python
def test_exec_injects_env_vars(runner, tmp_path):
    """exec command injects keys into child process environment."""
    import os
    import socket
    import threading
    import time
    from vaultsign.config import Config
    from vaultsign.keystore import Keystore
    from vaultsign.server import SignerServer

    home = tmp_path / ".vaultsign"
    home.mkdir()
    sock_path = str(home / "signer.sock")

    # Create keystore with opaque key
    ks = Keystore(str(home / "keystore.json"))
    ks.add_key(
        name="test-secret",
        key_type="opaque",
        address=None,
        private_key=bytearray(b"secret-value-123"),
        password=bytearray(b"testpass1234"),
    )
    ks.save()

    config = Config(home_dir=str(home), socket_path=sock_path, rate_limit=1000)
    server = SignerServer(config)
    server.load_keystore()
    server.unlock(bytearray(b"testpass1234"))

    t = threading.Thread(target=server.serve, daemon=True)
    t.start()

    # Wait for server ready
    if hasattr(socket, "AF_UNIX"):
        for _ in range(50):
            if os.path.exists(sock_path):
                break
            time.sleep(0.05)

    try:
        # exec should run a child process; verify via file output
        # (CliRunner does not capture subprocess stdout, so write to a file)
        out_file = str(tmp_path / "output.txt")
        result = runner.invoke(
            main,
            [
                "exec",
                "--inject", "test-secret=MY_SECRET",
                "--home", str(home),
                "--", "python", "-c",
                f"import os; open(r'{out_file}', 'w').write(os.environ.get('MY_SECRET', 'MISSING'))",
            ],
        )
        assert result.exit_code == 0, f"CLI output: {result.output}"
        assert open(out_file).read() == "secret-value-123"
    finally:
        server.shutdown()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py::test_exec_injects_env_vars -v`
Expected: FAIL with `No such command 'exec'`

- [ ] **Step 3: Implement `exec` command**

In `src/vaultsign/cli.py`, add:

```python
@main.command("exec", context_settings={"ignore_unknown_options": True})
@click.option("--inject", multiple=True, help="Inject key as env var: name=ENV_VAR")
@click.option("--home", default=None, help="Override home directory")
@click.argument("command", nargs=-1, type=click.UNPROCESSED, required=True)
def exec_cmd(inject, home, command):
    """Run a command with injected keys as environment variables."""
    import subprocess

    if not inject:
        raise click.ClickException("At least one --inject is required")

    config = _get_config(home)

    from .client import SignerClient
    from .errors import SignerError
    client = SignerClient(socket_path=config.socket_path)

    # Parse --inject args and retrieve keys
    env_vars = {}
    for mapping in inject:
        if "=" not in mapping:
            raise click.ClickException(
                f"Invalid --inject format: '{mapping}'. Use: name=ENV_VAR"
            )
        key_name, env_name = mapping.split("=", 1)
        try:
            key_value = client.get_key(key_name)
        except SignerError as e:
            raise click.ClickException(f"Failed to get key '{key_name}': {e}")
        env_vars[env_name] = key_value

    # Build child environment
    child_env = {**os.environ, **env_vars}

    # Run child process
    try:
        result = subprocess.run(list(command), env=child_env)
        raise SystemExit(result.returncode)
    except FileNotFoundError:
        raise click.ClickException(f"Command not found: {command[0]}")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cli.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/vaultsign/cli.py tests/test_cli.py
git commit -m "feat: add exec command for env var key injection"
```

---

### Task 9: Integration test — full get_key lifecycle

**Files:**
- Modify: `tests/test_integration.py`

- [ ] **Step 1: Write integration test**

In `tests/test_integration.py`, add:

```python
TEST_OPAQUE_KEY = "my-lighter-api-secret-key-value"


@pytest.fixture
def full_env_with_opaque(tmp_path):
    """Full integration environment with both EVM and opaque keys."""
    home = tmp_path / ".vaultsign"
    home.mkdir()
    sock_path = str(home / "signer.sock")

    ks = Keystore(str(home / "keystore.json"))
    ks.add_key(
        name="test-evm",
        key_type="secp256k1",
        address=TEST_EVM_ADDRESS,
        private_key=bytearray(TEST_EVM_KEY),
        password=bytearray(TEST_PASSWORD.encode()),
    )
    ks.add_key(
        name="lighter-api",
        key_type="opaque",
        address=None,
        private_key=bytearray(TEST_OPAQUE_KEY.encode("utf-8")),
        password=bytearray(TEST_PASSWORD.encode()),
    )
    ks.save()

    config = Config(
        home_dir=str(home),
        socket_path=sock_path,
        rate_limit=1000,
    )

    server = SignerServer(config)
    server.load_keystore()

    t = threading.Thread(target=server.serve, daemon=True)
    t.start()

    if _HAS_AF_UNIX:
        for _ in range(50):
            if os.path.exists(sock_path):
                break
            time.sleep(0.05)
    else:
        for _ in range(50):
            if server.server_address is not None:
                break
            time.sleep(0.05)

    client = SignerClient(socket_path=sock_path)

    yield server, client

    server.shutdown()


def test_get_key_opaque_lifecycle(full_env_with_opaque):
    """End-to-end: add opaque key, unlock, get_key, verify content."""
    server, client = full_env_with_opaque

    # Locked — get_key should fail
    from vaultsign.errors import SignerLockedError
    with pytest.raises(SignerLockedError):
        client.get_key("lighter-api")

    # Unlock
    client.unlock(password=TEST_PASSWORD)

    # get_key opaque
    key = client.get_key("lighter-api")
    assert key == TEST_OPAQUE_KEY

    # get_key EVM — also works
    evm_key = client.get_key("test-evm")
    assert len(evm_key) > 0  # got something back

    # Existing sign_transaction still works
    result = client.evm.sign_transaction({
        "to": "0x0000000000000000000000000000000000000000",
        "value": 0,
        "gas": 21000,
        "gasPrice": 1000000000,
        "nonce": 0,
        "chainId": 1,
    })
    assert "signed_tx" in result

    # get_key nonexistent
    from vaultsign.errors import KeyNotFoundError
    with pytest.raises(KeyNotFoundError):
        client.get_key("nonexistent")

    # Lock — get_key should fail again
    client.lock()
    with pytest.raises(SignerLockedError):
        client.get_key("lighter-api")
```

- [ ] **Step 2: Write change-password regression test**

In `tests/test_keystore.py`, add:

```python
def test_change_password_with_opaque_keys(tmp_path):
    """change-password flow works when keystore has both secp256k1 and opaque keys."""
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="my-evm",
        key_type="secp256k1",
        address="0xabc",
        private_key=bytearray(b"\x01" * 32),
        password=bytearray(b"oldpassword12"),
    )
    ks.add_key(
        name="lighter-api",
        key_type="opaque",
        address=None,
        private_key=bytearray(b"lighter-secret"),
        password=bytearray(b"oldpassword12"),
    )
    ks.save()

    # Decrypt with old password
    ks2 = Keystore.load(str(ks_path))
    keys = ks2.decrypt_all(bytearray(b"oldpassword12"))
    assert len(keys) == 2

    # Re-encrypt with new password (simulates change-password flow in cli.py)
    new_ks = Keystore(str(ks_path))
    for key in keys:
        new_ks.add_key(
            name=key.name,
            key_type=key.key_type,
            address=key.address,
            private_key=key.private_key,
            password=bytearray(b"newpassword12"),
        )
    new_ks.save()

    # Verify: decrypt with new password
    ks3 = Keystore.load(str(ks_path))
    keys3 = ks3.decrypt_all(bytearray(b"newpassword12"))
    assert len(keys3) == 2
    opaque_key = next(k for k in keys3 if k.key_type == "opaque")
    assert bytes(opaque_key.private_key) == b"lighter-secret"
    assert opaque_key.address is None
```

- [ ] **Step 3: Run the integration and regression tests**

Run: `uv run pytest tests/test_integration.py::test_get_key_opaque_lifecycle tests/test_keystore.py::test_change_password_with_opaque_keys -v`
Expected: PASS

- [ ] **Step 4: Run full test suite**

Run: `uv run pytest -v`
Expected: All PASS — no regressions

- [ ] **Step 5: Commit**

```bash
git add tests/test_integration.py tests/test_keystore.py
git commit -m "test: add integration and regression tests for key delivery"
```

---

### Task 10: Update SECURITY.md and __init__.py exports

**Files:**
- Modify: `SECURITY.md` (if it exists)
- Modify: `src/vaultsign/__init__.py`

- [ ] **Step 1: Ensure `KeyNotFoundError` is exported**

Verify `src/vaultsign/__init__.py` includes `KeyNotFoundError` in imports and `__all__` (should already be done in Task 1, but verify).

- [ ] **Step 2: Update SECURITY.md**

If `SECURITY.md` exists, add to the security boundaries section:

```markdown
### Key Delivery (`get_key`)

The `get_key` method delivers decrypted keys to the calling process via IPC.
Runtime security of the delivered key is the caller's responsibility. Callers
should clear keys from memory when no longer needed. For maximum security,
prefer `sign_transaction` over `get_key` when the signing model allows it.

The `exec` command injects keys as environment variables into a child process.
This is less secure than the IPC `get_key` method — keys persist in the process
environment for its lifetime and may be visible via `/proc/pid/environ` on Linux.
Use `exec` for convenience when IPC integration is not feasible.
```

- [ ] **Step 3: Run full test suite one final time**

Run: `uv run pytest -v`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add SECURITY.md src/vaultsign/__init__.py
git commit -m "docs: update security documentation for key delivery"
```
