# Review Findings Fix Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix three confirmed code review findings: Windows ACL hardening, client key decoding, and transport selection.

**Architecture:** Three independent fixes applied in order 3 → 2 → 1 per spec. Finding 3 (transport) changes module-level imports in `client.py` and `server.py`; Finding 2 (key decoding) changes `client.py` method internals; Finding 1 (ACL) is isolated to `platform_win.py`. TDD throughout.

**Tech Stack:** Python 3.10+, pytest, unittest.mock. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-03-20-review-findings-fix-design.md`

**Test runner:** `uv run pytest tests/ -q`

---

## File Map

| Action | File | Responsibility |
|--------|------|----------------|
| Create | `src/vaultsign/transport.py` | Centralized transport mode policy |
| Create | `tests/test_transport.py` | Tests for transport policy |
| Modify | `src/vaultsign/server.py:1-36,331-336` | Replace `_HAS_AF_UNIX` with `transport.get_transport_mode()` |
| Modify | `src/vaultsign/client.py:1-11,62-71,98-105` | Replace `_HAS_AF_UNIX`, add `KeyInfo`/`get_key_info()`, rewrite `get_key()` |
| Modify | `src/vaultsign/security/platform_win.py:29-65` | Extract fallback chain functions |
| Modify | `tests/test_server.py:579-615` | Migrate `_HAS_AF_UNIX` patch |
| Modify | `tests/test_client.py:16,29-78,84-89,138-171,225-245` | Migrate all `_HAS_AF_UNIX` usage |
| Modify | `tests/test_integration.py:25,61-71,182-191,215-219` | Migrate `_HAS_AF_UNIX`, replace `_send()` workaround |
| Modify | `tests/test_platform.py` | Add pywin32 runtime failure tests |

---

## Task 1: Create transport module with tests

**Files:**
- Create: `src/vaultsign/transport.py`
- Create: `tests/test_transport.py`

- [ ] **Step 1: Write the failing tests for transport policy**

Create `tests/test_transport.py`:

```python
"""Tests for transport mode selection policy."""

import socket
import types
from unittest.mock import patch

from vaultsign.transport import get_transport_mode


def test_windows_always_tcp_even_with_af_unix():
    """Windows must use TCP regardless of AF_UNIX availability."""
    # Create a mock socket module that HAS AF_UNIX, to prove Windows ignores it
    mock_socket = types.ModuleType("socket")
    mock_socket.AF_UNIX = 1  # present
    with patch("vaultsign.transport.sys") as mock_sys, \
         patch("vaultsign.transport.socket", mock_socket):
        mock_sys.platform = "win32"
        assert get_transport_mode() == "tcp"


def test_linux_with_af_unix_uses_unix():
    """Linux with AF_UNIX should prefer Unix sockets."""
    mock_socket = types.ModuleType("socket")
    mock_socket.AF_UNIX = 1  # present
    with patch("vaultsign.transport.sys") as mock_sys, \
         patch("vaultsign.transport.socket", mock_socket):
        mock_sys.platform = "linux"
        assert get_transport_mode() == "unix"


def test_no_af_unix_falls_back_to_tcp():
    """Any platform without AF_UNIX should fall back to TCP."""
    # Create a mock socket module that lacks AF_UNIX entirely
    mock_socket = types.ModuleType("socket")
    # no AF_UNIX attribute
    with patch("vaultsign.transport.sys") as mock_sys, \
         patch("vaultsign.transport.socket", mock_socket):
        mock_sys.platform = "linux"
        assert get_transport_mode() == "tcp"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_transport.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'vaultsign.transport'`

- [ ] **Step 3: Write the transport module**

Create `src/vaultsign/transport.py`:

```python
"""Transport mode selection policy.

Windows always uses TCP with token-based auth.
Other platforms prefer Unix domain sockets when available.
"""

import socket
import sys
from typing import Literal


def get_transport_mode() -> Literal["unix", "tcp"]:
    """Return the transport mode for the current platform.

    Windows always uses TCP with token auth.
    Other platforms prefer Unix domain sockets when available.
    """
    if sys.platform == "win32":
        return "tcp"
    if hasattr(socket, "AF_UNIX"):
        return "unix"
    return "tcp"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_transport.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
git add src/vaultsign/transport.py tests/test_transport.py
git commit -m "feat: add centralized transport mode selection module"
```

---

## Task 2: Migrate server.py to use transport module

**Files:**
- Modify: `src/vaultsign/server.py:1-5,36,331-336`
- Modify: `tests/test_server.py:579-615`

- [ ] **Step 1: Update server.py imports and transport decision**

In `src/vaultsign/server.py`:

1. Update the module docstring (lines 2-4) from:
   ```python
   """IPC signing server.

   Uses Unix domain sockets on Linux/macOS and TCP localhost on Windows.
   """
   ```
   to:
   ```python
   """IPC signing server.

   Transport mode is determined by vaultsign.transport.get_transport_mode():
   Unix domain sockets on Linux/macOS, TCP localhost on Windows.
   """
   ```

2. Add import after line 14 (after existing imports, before the error imports):
   ```python
   from vaultsign import transport
   ```

3. Remove line 36:
   ```python
   _HAS_AF_UNIX = hasattr(socket, "AF_UNIX")
   ```

4. In `serve()` method (lines 331-336), replace:
   ```python
   if _HAS_AF_UNIX:
   ```
   with:
   ```python
   if transport.get_transport_mode() == "unix":
   ```

- [ ] **Step 2: Migrate test_server.py TCP token auth test**

In `tests/test_server.py`, replace lines 579-615. The `test_tcp_token_auth` function currently patches `server_mod._HAS_AF_UNIX = False`. Replace with:

```python
def test_tcp_token_auth(server_env):
    """TCP mode requires a valid token; requests without it are rejected."""
    config, ks_path, sock_path = server_env
    server = SignerServer(config)
    server.load_keystore()

    from unittest.mock import patch

    with patch("vaultsign.transport.get_transport_mode", return_value="tcp"):
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

        server.shutdown()
```

- [ ] **Step 3: Run all tests to verify no regressions**

Run: `uv run pytest tests/test_server.py tests/test_transport.py -v`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add src/vaultsign/server.py tests/test_server.py
git commit -m "refactor: migrate server.py transport decision to transport module"
```

---

## Task 3: Migrate client.py to use transport module

**Files:**
- Modify: `src/vaultsign/client.py:1-11,62-71,98-105`
- Modify: `tests/test_client.py:16,29-78,84-89,138-171,225-245`
- Modify: `tests/test_integration.py:25,61-71,182-191`

- [ ] **Step 1: Update client.py imports and transport decision**

In `src/vaultsign/client.py`:

1. Add import after line 7 (after `from pathlib import Path`):
   ```python
   from vaultsign import transport
   ```

2. Remove line 11:
   ```python
   _HAS_AF_UNIX = hasattr(socket, "AF_UNIX")
   ```

3. In `__init__` (lines 62-71), replace all `_HAS_AF_UNIX` references:
   ```python
        if socket_path and not _HAS_AF_UNIX:
   ```
   becomes:
   ```python
        if socket_path and transport.get_transport_mode() != "unix":
   ```
   and:
   ```python
            if _HAS_AF_UNIX:
   ```
   becomes:
   ```python
            if transport.get_transport_mode() == "unix":
   ```

4. In `_connect` (line 101), replace:
   ```python
        if self._socket_path and _HAS_AF_UNIX:
   ```
   with:
   ```python
        if self._socket_path and transport.get_transport_mode() == "unix":
   ```

- [ ] **Step 2: Migrate test_client.py _HAS_AF_UNIX usage**

In `tests/test_client.py`:

1. Remove line 16:
   ```python
   _HAS_AF_UNIX = hasattr(socket, "AF_UNIX")
   ```

2. Add at line 16:
   ```python
   from vaultsign import transport
   _USE_UNIX = transport.get_transport_mode() == "unix"
   ```

3. Replace all occurrences of `_HAS_AF_UNIX` in the file with `_USE_UNIX`. There are references at lines 29, 61, 69, 143, 163.

4. In `test_default_client_reads_discovery_files_on_windows` (lines 225-233), replace:
   ```python
    with patch("vaultsign.client._HAS_AF_UNIX", False), \
   ```
   with:
   ```python
    with patch("vaultsign.transport.get_transport_mode", return_value="tcp"), \
   ```

5. In `test_default_client_raises_when_no_discovery_files` (lines 241-245), replace:
   ```python
    with patch("vaultsign.client._HAS_AF_UNIX", False), \
   ```
   with:
   ```python
    with patch("vaultsign.transport.get_transport_mode", return_value="tcp"), \
   ```

- [ ] **Step 3: Migrate test_integration.py _HAS_AF_UNIX usage**

In `tests/test_integration.py`:

1. Replace line 25:
   ```python
   _HAS_AF_UNIX = hasattr(socket, "AF_UNIX")
   ```
   with:
   ```python
   from vaultsign import transport
   _USE_UNIX = transport.get_transport_mode() == "unix"
   ```

2. Replace all `_HAS_AF_UNIX` references with `_USE_UNIX` (lines 61, 182).

- [ ] **Step 4: Run full test suite to verify no regressions**

Run: `uv run pytest tests/ -q`
Expected: 118 passed (same count as before)

- [ ] **Step 5: Commit**

```bash
git add src/vaultsign/client.py tests/test_client.py tests/test_integration.py
git commit -m "refactor: migrate client.py and tests to transport module"
```

---

## Task 4: Add KeyInfo dataclass and get_key_info method

**Files:**
- Modify: `src/vaultsign/client.py:1-9,165-176`

- [ ] **Step 1: Write the failing test for key type-based decoding**

Add to `tests/test_client.py` after the existing `test_get_key_returns_decoded_string` test (around line 215):

```python
def test_get_key_binary_key_valid_utf8_returns_hex():
    """A binary key whose bytes happen to be valid UTF-8 must return hex, not text."""
    # 32 bytes of 0x41 is valid UTF-8 ("AAA...") but is a secp256k1 key → must be hex
    binary_key = bytes([0x41] * 32)
    mock_result = {
        "name": "test-evm",
        "key_type": "secp256k1",
        "key": base64.b64encode(binary_key).decode(),
        "address": "0x1234",
    }

    client = SignerClient(host="127.0.0.1", port=9999)
    with patch.object(client, "_send", return_value=mock_result):
        result = client.get_key("test-evm")

    assert result == "41" * 32  # hex, not "A" * 32


def test_get_key_info_returns_dataclass():
    """get_key_info returns a KeyInfo with value, key_type, address."""
    original_key = "my-secret"
    mock_result = {
        "name": "test-opaque",
        "key_type": "opaque",
        "key": base64.b64encode(original_key.encode()).decode(),
        "address": None,
    }

    client = SignerClient(host="127.0.0.1", port=9999)
    with patch.object(client, "_send", return_value=mock_result):
        info = client.get_key_info("test-opaque")

    assert info.value == "my-secret"
    assert info.key_type == "opaque"
    assert info.address is None


def test_get_key_info_missing_key_type_raises():
    """If server response lacks key_type, raise IPCProtocolError."""
    mock_result = {
        "name": "test",
        "key": base64.b64encode(b"data").decode(),
        "address": None,
    }

    client = SignerClient(host="127.0.0.1", port=9999)
    with patch.object(client, "_send", return_value=mock_result):
        with pytest.raises(IPCProtocolError, match="key_type"):
            client.get_key_info("test")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_client.py::test_get_key_binary_key_valid_utf8_returns_hex tests/test_client.py::test_get_key_info_returns_dataclass tests/test_client.py::test_get_key_info_missing_key_type_raises -v`
Expected: FAIL — `test_get_key_binary_key_valid_utf8_returns_hex` returns `"A" * 32` instead of hex; `get_key_info` does not exist.

- [ ] **Step 3: Implement KeyInfo and get_key_info in client.py**

In `src/vaultsign/client.py`:

1. Add `import dataclasses` and `import logging` to the top imports (after `import base64`).

2. Add after the imports (before `_MAX_RESPONSE`):
   ```python
   logger = logging.getLogger(__name__)


   @dataclasses.dataclass
   class KeyInfo:
       """Decrypted key metadata and formatted value.

       Mutable to allow callers to clear value after use (info.value = "").
       Does not hold raw key bytes — only the formatted string representation.
       """
       value: str
       key_type: str
       address: str | None
   ```

3. Add `get_key_info` method to `SignerClient` (before `get_key`):
   ```python
       def get_key_info(self, name: str) -> KeyInfo:
           """Retrieve a decrypted key with metadata.

           Returns a KeyInfo with the formatted value, key_type, and address.
           Format is determined by key_type: opaque keys are UTF-8 decoded,
           all other types are hex-encoded.
           """
           result = self._send("get_key", {"name": name})
           if "key_type" not in result:
               raise IPCProtocolError(
                   "Server response missing 'key_type' field. "
                   "This may indicate a protocol version mismatch."
               )
           key_bytes = base64.b64decode(result["key"])
           key_type = result["key_type"]
           if key_type == "opaque":
               try:
                   value = key_bytes.decode("utf-8")
               except UnicodeDecodeError:
                   logger.warning(
                       "Opaque key %r contains non-UTF-8 bytes; returning hex",
                       name,
                   )
                   value = key_bytes.hex()
           else:
               value = key_bytes.hex()
           return KeyInfo(
               value=value,
               key_type=key_type,
               address=result.get("address"),
           )
   ```

4. Rewrite `get_key` to delegate:
   ```python
       def get_key(self, name: str) -> str:
           """Retrieve a decrypted key by name.

           Returns the key as a string: UTF-8 decoded for opaque keys,
           hex-encoded for binary keys (e.g., secp256k1).
           """
           return self.get_key_info(name).value
   ```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_client.py -v`
Expected: All pass

- [ ] **Step 5: Update existing get_key test to match new behavior**

The existing `test_get_key_returns_decoded_string` (line 200) already has `"key_type": "opaque"` in the mock result. Verify it still passes — it should, since opaque keys are still UTF-8 decoded.

Run: `uv run pytest tests/test_client.py::test_get_key_returns_decoded_string -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add src/vaultsign/client.py tests/test_client.py
git commit -m "fix: use key_type metadata for key format decision in get_key()"
```

---

## Task 5: Update integration test to use get_key() for EVM keys

**Files:**
- Modify: `tests/test_integration.py:215-219`

- [ ] **Step 1: Replace the _send() workaround**

In `tests/test_integration.py`, replace lines 215-219:

```python
    # get_key EVM — also works (raw binary key, use _send to avoid UTF-8 decode)
    import base64
    result = client._send("get_key", {"name": "test-evm"})
    evm_key_bytes = base64.b64decode(result["key"])
    assert len(evm_key_bytes) > 0
```

with:

```python
    # get_key EVM — now correctly returns hex via key_type metadata
    evm_key = client.get_key("test-evm")
    assert evm_key == TEST_EVM_KEY.hex()
```

- [ ] **Step 2: Run the integration test to verify**

Run: `uv run pytest tests/test_integration.py::test_get_key_opaque_lifecycle -v`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/test_integration.py
git commit -m "test: replace _send() workaround with direct get_key() for EVM keys"
```

---

## Task 6: Export KeyInfo from package

**Files:**
- Modify: `src/vaultsign/__init__.py`

- [ ] **Step 1: Add KeyInfo to package exports**

In `src/vaultsign/__init__.py`, add to the import from `.client`:

Change line 3:
```python
from .client import SignerClient
```
to:
```python
from .client import SignerClient, KeyInfo
```

Add `"KeyInfo"` to the `__all__` list.

- [ ] **Step 2: Run tests**

Run: `uv run pytest tests/ -q`
Expected: All pass

- [ ] **Step 3: Commit**

```bash
git add src/vaultsign/__init__.py
git commit -m "feat: export KeyInfo from package"
```

---

## Task 7: Refactor platform_win.py ACL hardening — tests first

**Files:**
- Modify: `tests/test_platform.py`

- [ ] **Step 1: Write failing tests for pywin32 runtime failure**

Add to `tests/test_platform.py`:

```python
def test_set_file_owner_only_pywin32_error_falls_back_to_icacls(tmp_path, caplog):
    """When pywin32 imports succeed but SetFileSecurity raises, fall back to icacls."""
    if sys.platform != "win32":
        pytest.skip("Windows-only test")

    from unittest.mock import MagicMock
    from vaultsign.security.platform_win import set_file_owner_only

    f = tmp_path / "test.txt"
    f.write_text("data")

    # Create a fake pywintypes.error
    class FakePywinError(Exception):
        pass

    mock_win32api = MagicMock()
    mock_win32security = MagicMock()
    mock_ntsecuritycon = MagicMock()
    mock_pywintypes = MagicMock()
    mock_pywintypes.error = FakePywinError
    mock_win32security.SetFileSecurity.side_effect = FakePywinError("access denied")

    with patch.dict("sys.modules", {
        "win32api": mock_win32api,
        "win32security": mock_win32security,
        "ntsecuritycon": mock_ntsecuritycon,
        "pywintypes": mock_pywintypes,
    }), \
         patch("vaultsign.security.platform_win.subprocess.run") as mock_run, \
         caplog.at_level(logging.WARNING):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stderr=b"",
        )
        set_file_owner_only(str(f))

    # Should have fallen back to icacls
    mock_run.assert_called_once()
    assert "icacls" in mock_run.call_args[0][0][0]


def test_set_file_owner_only_both_methods_fail_no_exception(tmp_path, caplog):
    """When both pywin32 and icacls fail, warn but don't raise."""
    if sys.platform != "win32":
        pytest.skip("Windows-only test")

    from unittest.mock import MagicMock
    from vaultsign.security.platform_win import set_file_owner_only

    f = tmp_path / "test.txt"
    f.write_text("data")

    class FakePywinError(Exception):
        pass

    mock_win32api = MagicMock()
    mock_win32security = MagicMock()
    mock_ntsecuritycon = MagicMock()
    mock_pywintypes = MagicMock()
    mock_pywintypes.error = FakePywinError
    mock_win32security.SetFileSecurity.side_effect = FakePywinError("access denied")

    with patch.dict("sys.modules", {
        "win32api": mock_win32api,
        "win32security": mock_win32security,
        "ntsecuritycon": mock_ntsecuritycon,
        "pywintypes": mock_pywintypes,
    }), \
         patch("vaultsign.security.platform_win.subprocess.run") as mock_run, \
         caplog.at_level(logging.WARNING):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stderr=b"access denied",
        )
        # Should NOT raise
        set_file_owner_only(str(f))

    assert "icacls failed" in caplog.text


def test_set_file_owner_only_pywin32_success_no_icacls(tmp_path):
    """When pywin32 succeeds, icacls should not be called."""
    if sys.platform != "win32":
        pytest.skip("Windows-only test")

    from unittest.mock import MagicMock
    from vaultsign.security.platform_win import set_file_owner_only

    f = tmp_path / "test.txt"
    f.write_text("data")

    mock_win32api = MagicMock()
    mock_win32security = MagicMock()
    mock_ntsecuritycon = MagicMock()
    mock_ntsecuritycon.TOKEN_QUERY = 0x0008
    mock_ntsecuritycon.FILE_ALL_ACCESS = 0x1F01FF

    with patch.dict("sys.modules", {
        "win32api": mock_win32api,
        "win32security": mock_win32security,
        "ntsecuritycon": mock_ntsecuritycon,
    }), \
         patch("vaultsign.security.platform_win.subprocess.run") as mock_run:
        set_file_owner_only(str(f))

    # icacls should NOT have been called
    mock_run.assert_not_called()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_platform.py::test_set_file_owner_only_pywin32_error_falls_back_to_icacls tests/test_platform.py::test_set_file_owner_only_both_methods_fail_no_exception tests/test_platform.py::test_set_file_owner_only_pywin32_success_no_icacls -v`
Expected: First test FAILs because the pywin32 error propagates uncaught (this is the bug). Third test may pass already.

- [ ] **Step 3: Commit the failing tests**

```bash
git add tests/test_platform.py
git commit -m "test: add failing tests for pywin32 runtime error fallback"
```

---

## Task 8: Implement ACL hardening fallback chain

**Files:**
- Modify: `src/vaultsign/security/platform_win.py:29-65`

- [ ] **Step 1: Refactor set_file_owner_only into fallback chain**

Replace lines 29-65 of `src/vaultsign/security/platform_win.py` with:

```python
def _set_acl_pywin32(path: str) -> None:
    """Set file ACL to owner-only using pywin32 APIs.

    Raises ImportError if pywin32 is not installed.
    Raises pywintypes.error or OSError on ACL operation failure.
    """
    import win32api
    import win32security
    import ntsecuritycon as con

    user_sid = win32security.GetTokenInformation(
        win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), con.TOKEN_QUERY
        ),
        win32security.TokenUser,
    )[0]
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAce(
        win32security.ACL_REVISION, con.FILE_ALL_ACCESS, user_sid,
    )
    sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
    sd.SetSecurityDescriptorDacl(True, dacl, False)
    win32security.SetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION, sd)


def _set_acl_icacls(path: str) -> bool:
    """Set file ACL to owner-only using icacls.

    Returns True on success, False on failure. Never raises.
    """
    domain = os.environ.get("USERDOMAIN", "")
    username = os.environ.get("USERNAME", "")
    if not username:
        logger.warning(
            "Cannot set file permissions: USERNAME env var not set"
        )
        return False
    qualified = f"{domain}\\{username}" if domain else username
    try:
        result = subprocess.run(
            ["icacls", path, "/inheritance:r", "/grant:r", f"{qualified}:(F)"],
            capture_output=True,
        )
    except OSError as e:
        logger.warning("Failed to launch icacls: %s", e)
        return False
    if result.returncode != 0:
        logger.warning(
            "icacls failed (rc=%d): %s",
            result.returncode,
            result.stderr.decode(errors="replace").strip(),
        )
        return False
    return True


def set_file_owner_only(path: str) -> None:
    """Restrict file access to the current user only.

    Tries pywin32 APIs first, falls back to icacls, then warns on total
    failure. Never raises — callers do not need error handling.
    """
    try:
        _set_acl_pywin32(path)
        return
    except ImportError:
        logger.debug("pywin32 not available, trying icacls")
    except Exception as e:
        logger.warning("pywin32 ACL operation failed: %s; trying icacls", e)

    _set_acl_icacls(path)
```

- [ ] **Step 2: Run the new tests to verify they pass**

Run: `uv run pytest tests/test_platform.py -v`
Expected: All pass (including the new tests from Task 7)

- [ ] **Step 3: Run full test suite**

Run: `uv run pytest tests/ -q`
Expected: 118 passed (or more, with new tests)

- [ ] **Step 4: Commit**

```bash
git add src/vaultsign/security/platform_win.py
git commit -m "fix: ACL hardening falls back to icacls on pywin32 runtime errors"
```

---

## Task 9: Final verification

- [ ] **Step 1: Run the full test suite**

Run: `uv run pytest tests/ -q`
Expected: All pass (count should be 118 + new tests)

- [ ] **Step 2: Verify no references to _HAS_AF_UNIX remain in source**

Run: `grep -r "_HAS_AF_UNIX" src/ tests/`
Expected: No output (all references removed from source and tests)

- [ ] **Step 3: Verify no content sniffing remains in get_key**

Run: `grep -n "UnicodeDecodeError" src/vaultsign/client.py`
Expected: Only in `get_key_info`'s opaque fallback path, not in `get_key` itself

- [ ] **Step 4: Commit any remaining cleanup**

Only if needed. Otherwise, done.
