# Review Findings Fix — Design Spec

Date: 2026-03-20
Status: Draft
Source: `docs/review-findings-2026-03-20.txt`

## Context

A code review identified three confirmed issues in VaultSign:

1. **High:** Windows ACL hardening crashes on OS-level permission errors
2. **Medium:** `get_key()` misclassifies binary keys as text via UTF-8 content sniffing
3. **Medium:** Windows transport selection is implicit and diverges from documentation

All three are confirmed by source analysis. Tests pass (118 passed) but do not cover these edge cases. This spec describes a refactor that fixes all three while improving code quality in the affected modules.

## Decisions

| Finding | Chosen approach |
|---------|----------------|
| 1. ACL hardening | Fallback chain: pywin32 → icacls → warn and continue |
| 2. Key decoding | Use `key_type` metadata instead of content sniffing; return `str` |
| 3. Transport policy | Always TCP on Windows; explicit `sys.platform` check |

Overall approach: broader refactor pass — fix the bugs and improve code quality in the touched modules.

---

## 1. Windows ACL Hardening Refactor

### Files

- `src/vaultsign/security/platform_win.py` (primary)
- Tests: new cases in existing test file or new `tests/test_platform_win.py`

### Current behavior

`set_file_owner_only()` is a single function. The pywin32 block is wrapped in `try/except ImportError`. If pywin32 imports successfully but `SetFileSecurity()` raises `pywintypes.error`, the exception propagates uncaught, crashing the caller (`keystore.save()`, server startup, etc.).

### New design

Extract two internal functions:

```
_set_acl_pywin32(path: str) -> None
    Raises: ImportError, pywintypes.error, OSError

_set_acl_icacls(path: str) -> None
    Raises: OSError, subprocess.CalledProcessError
```

Orchestrator `set_file_owner_only(path: str) -> None`:

1. Try `_set_acl_pywin32(path)`.
2. On `ImportError` or `pywintypes.error` or `OSError`: log warning, try `_set_acl_icacls(path)`.
3. On icacls failure: log warning, return without raising.

The function never raises. Callers do not need to change.

Add `logger = logging.getLogger(__name__)` for all warning output.

### New tests

- Mock `SetFileSecurity` raising `pywintypes.error` → verify icacls fallback is attempted.
- Mock both pywin32 and icacls failing → verify warning is logged, no exception propagates.
- Happy path: pywin32 succeeds → verify icacls is not called.

---

## 2. Client Key Decoding Refactor

### Files

- `src/vaultsign/client.py` (primary)
- `src/vaultsign/cli.py` (no code change needed, behavior corrected upstream)
- `tests/test_integration.py` (remove `_send()` workaround)
- Tests: new regression test

### Current behavior

`get_key()` base64-decodes the key bytes, tries UTF-8 decode, falls back to hex on `UnicodeDecodeError`. The server response includes `key_type` but the client ignores it. Binary keys that happen to be valid UTF-8 are silently returned as text strings.

### New design

Add a `KeyInfo` dataclass:

```python
@dataclasses.dataclass(frozen=True)
class KeyInfo:
    value: str       # Formatted key (UTF-8 text or hex)
    key_type: str    # "opaque", "secp256k1", etc.
    raw_bytes: bytes # Raw key bytes
    address: str     # Key address (empty string if N/A)
```

Add `get_key_info(name: str) -> KeyInfo`:

- Calls `self._send("get_key", {"name": name})`
- Reads `result["key_type"]` to decide format:
  - `"opaque"` → `value = key_bytes.decode("utf-8")`
  - All other types → `value = key_bytes.hex()`
- Returns `KeyInfo` with all fields populated

Rewrite `get_key(name: str) -> str` as:

```python
def get_key(self, name: str) -> str:
    return self.get_key_info(name).value
```

No content sniffing. No try/except `UnicodeDecodeError`.

### Caller impact

- `get_key()` signature unchanged (`str` → `str`). All existing callers work.
- `cli.py` `exec_cmd` continues calling `get_key()` — behavior is now correct.
- `get_key_info()` is available for callers needing richer access.

### Test changes

- New regression test: create a secp256k1 key whose raw bytes are valid UTF-8 (e.g., 32 bytes of `0x41`). Call `get_key()`, assert result is hex (`"41" * 32`), not text (`"A" * 32`).
- Update `test_integration.py`: replace the `_send()` workaround for EVM key retrieval with a direct `get_key()` call, verifying it now returns hex correctly.

---

## 3. Transport Selection Refactor

### Files

- New: `src/vaultsign/transport.py`
- Modified: `src/vaultsign/server.py`, `src/vaultsign/client.py`
- New: `tests/test_transport.py`
- Modified: `tests/test_server.py`

### Current behavior

Both `server.py` and `client.py` define `_HAS_AF_UNIX = hasattr(socket, "AF_UNIX")` at module level. Transport decision is implicit and duplicated. On modern Windows Python where AF_UNIX exists, the code prefers Unix sockets despite the docstring saying "TCP localhost on Windows."

### New design

New module `src/vaultsign/transport.py`:

```python
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

Changes to `server.py`:

- Remove `_HAS_AF_UNIX = hasattr(socket, "AF_UNIX")`
- Import `get_transport_mode` from `transport.py`
- Replace `if _HAS_AF_UNIX:` with `if get_transport_mode() == "unix":`
- Update module docstring to reference explicit platform policy

Changes to `client.py`:

- Remove `_HAS_AF_UNIX = hasattr(socket, "AF_UNIX")`
- Import `get_transport_mode` from `transport.py`
- Replace all `_HAS_AF_UNIX` checks with `get_transport_mode() == "unix"`

### New tests (`tests/test_transport.py`)

- Patch `sys.platform = "win32"` + AF_UNIX available → assert `"tcp"`
- Patch `sys.platform = "linux"` + AF_UNIX available → assert `"unix"`
- Patch AF_UNIX absent on any platform → assert `"tcp"`

### Test migration (`tests/test_server.py`)

- Replace `server_mod._HAS_AF_UNIX = False` patch with `unittest.mock.patch("vaultsign.transport.get_transport_mode", return_value="tcp")`

---

## 4. Cross-cutting Quality Improvements

### Logging

- `platform_win.py`: add `logger = logging.getLogger(__name__)`. Use `logger.warning()` for fallback and failure messages.
- Verify `server.py` and `client.py` follow the same pattern.

### Type annotations

- `KeyInfo` dataclass provides typed access to key data.
- `get_transport_mode()` uses `Literal["unix", "tcp"]`.
- `set_file_owner_only()` documents that it never raises.

### Test hygiene

- Remove `_send()` workaround in `test_integration.py`.
- Replace raw `_HAS_AF_UNIX` patching with `transport.get_transport_mode` mock.

### Scope boundaries

- Only touch modules related to the three findings.
- No reformatting, no docstring additions to untouched code, no dependency changes.

---

## Out of scope

- Refactoring unrelated modules
- Adding new CLI commands or flags
- Changing the keystore format
- Modifying the server protocol
