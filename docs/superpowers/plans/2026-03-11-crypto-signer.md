# crypto-signer Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a pip-installable Python package that provides encrypted wallet storage + memory-resident signing service for crypto automation, supporting EVM and Solana chains across Linux, macOS, and Windows.

**Architecture:** A daemon process holds decrypted private keys in memory and serves signing requests over a Unix domain socket. Keys are encrypted at rest with AES-256-GCM (password derived via Argon2id). A client library provides a simple Python API. A CLI manages keystore initialization, service lifecycle, and lock/unlock operations.

**Tech Stack:** Python 3.10+, click (CLI), argon2-cffi (KDF), cryptography (AEAD), eth-account (EVM), solders (Solana), bip-utils (mnemonic derivation), tomli (config)

**Spec:** `docs/superpowers/specs/2026-03-11-crypto-signer-design.md`

---

## File Structure

All source lives under `src/crypto_signer/`. Tests mirror the source layout under `tests/`.

| File | Responsibility |
|------|---------------|
| `pyproject.toml` | Package metadata, dependencies, CLI entry point |
| `src/crypto_signer/__init__.py` | Public API: exports `SignerClient`, errors |
| `src/crypto_signer/errors.py` | All exception classes and error codes |
| `src/crypto_signer/security/zeroize.py` | `SecureByteArray` wrapper + `zeroize()` helper |
| `src/crypto_signer/security/platform.py` | Platform dispatch (imports Unix or Win module) |
| `src/crypto_signer/security/platform_unix.py` | `mlock`, `prctl`, `SO_PEERCRED`, `chmod 0600` |
| `src/crypto_signer/security/platform_win.py` | `VirtualLock`, ACL via `icacls`, no peer creds |
| `src/crypto_signer/security/harden.py` | High-level `harden_process()` + `check_swap()` |
| `src/crypto_signer/security/safe_input.py` | `secure_getpass()` returning `bytearray` |
| `src/crypto_signer/config.py` | Load `config.toml`, merge defaults |
| `src/crypto_signer/keystore.py` | Encrypt/decrypt/read/write `keystore.json` |
| `src/crypto_signer/crypto/evm.py` | EVM signing engine: sign tx, message, typed data |
| `src/crypto_signer/crypto/solana.py` | Solana signing engine: sign tx, message |
| `src/crypto_signer/state.py` | `SignerState` enum + `SignerStateMachine` |
| `src/crypto_signer/server.py` | Unix socket server, request dispatch, rate limiter |
| `src/crypto_signer/client.py` | `SignerClient` with `.evm` / `.solana` sub-objects |
| `src/crypto_signer/cli.py` | All CLI commands (click) |
| `src/crypto_signer/web3/middleware.py` | web3.py `SignerMiddleware` |

---

## Chunk 1: Foundation

### Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `src/crypto_signer/__init__.py`
- Create: `src/crypto_signer/security/__init__.py`
- Create: `src/crypto_signer/crypto/__init__.py`
- Create: `src/crypto_signer/web3/__init__.py`
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`
- Create: `.gitignore`

- [ ] **Step 1: Create pyproject.toml**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "crypto-signer"
version = "0.1.0"
description = "Encrypted wallet + memory-resident signing service for crypto automation"
readme = "README.md"
requires-python = ">=3.10"
license = "MIT"
dependencies = [
    "click>=8.0",
    "argon2-cffi>=23.1",
    "cryptography>=41.0",
    "eth-account>=0.11",
    "solders>=0.21",
    "bip-utils>=2.9",
    "tomli>=2.0; python_version < '3.11'",
]

[project.optional-dependencies]
web3 = ["web3>=6.0"]
win = ["pywin32>=306"]
dev = [
    "pytest>=7.0",
    "pytest-asyncio>=0.21",
]

[project.scripts]
crypto-signer = "crypto_signer.cli:main"

[tool.hatch.build.targets.wheel]
packages = ["src/crypto_signer"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
```

- [ ] **Step 2: Create directory structure and __init__ files**

Create empty `__init__.py` in:
- `src/crypto_signer/__init__.py` (will be populated later)
- `src/crypto_signer/security/__init__.py`
- `src/crypto_signer/crypto/__init__.py`
- `src/crypto_signer/web3/__init__.py`
- `tests/__init__.py`

Create `tests/conftest.py`:
```python
import os
import tempfile

import pytest


@pytest.fixture
def tmp_home(tmp_path):
    """Provide a temporary home directory for tests."""
    home = tmp_path / ".crypto-signer"
    home.mkdir()
    return home


@pytest.fixture
def keystore_path(tmp_home):
    """Path to a temporary keystore.json."""
    return tmp_home / "keystore.json"
```

- [ ] **Step 3: Create .gitignore**

```
__pycache__/
*.pyc
*.egg-info/
dist/
build/
.venv/
*.sock
*.pid
.env
```

- [ ] **Step 4: Initialize git repo and commit**

```bash
cd "E:/OneDrive/00-personal-archive/crypto/crypto-signer"
git init
git add pyproject.toml src/ tests/ .gitignore
git commit -m "feat: initialize project scaffolding"
```

---

### Task 2: Error Definitions

**Files:**
- Create: `src/crypto_signer/errors.py`
- Create: `tests/test_errors.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_errors.py
from crypto_signer.errors import (
    SignerError,
    SignerConnectionError,
    SignerLockedError,
    SignerStateError,
    InvalidPasswordError,
    SigningError,
    UnsupportedChainError,
    PolicyViolationError,
    WalletFormatError,
    IPCProtocolError,
    PermissionDeniedError,
    ErrorCode,
)


def test_all_errors_inherit_from_signer_error():
    errors = [
        SignerConnectionError,
        SignerLockedError,
        SignerStateError,
        InvalidPasswordError,
        SigningError,
        UnsupportedChainError,
        PolicyViolationError,
        WalletFormatError,
        IPCProtocolError,
        PermissionDeniedError,
    ]
    for err_cls in errors:
        assert issubclass(err_cls, SignerError)


def test_error_codes_are_unique():
    codes = [e.value for e in ErrorCode]
    assert len(codes) == len(set(codes))


def test_signer_locked_error_has_correct_code():
    err = SignerLockedError("test")
    assert err.code == ErrorCode.SIGNER_LOCKED
    assert err.code.value == 1001


def test_error_to_dict():
    err = SignerLockedError("signer is locked")
    d = err.to_dict()
    assert d == {"code": 1001, "message": "signer is locked"}


def test_error_from_dict():
    d = {"code": 1001, "message": "signer is locked"}
    err = SignerError.from_dict(d)
    assert isinstance(err, SignerLockedError)
    assert str(err) == "signer is locked"


def test_error_repr_does_not_leak_secrets():
    err = SigningError("failed to sign")
    r = repr(err)
    assert "SigningError" in r
    assert "failed to sign" in r
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd "E:/OneDrive/00-personal-archive/crypto/crypto-signer" && python -m pytest tests/test_errors.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write the implementation**

```python
# src/crypto_signer/errors.py
"""Error definitions for crypto-signer.

Error messages MUST NEVER contain plaintext passwords, private keys, or mnemonics.
"""

from enum import IntEnum


class ErrorCode(IntEnum):
    SIGNER_LOCKED = 1001
    SIGNER_STATE = 1002
    INVALID_PASSWORD = 1003
    SIGNING = 1004
    UNSUPPORTED_CHAIN = 1005
    POLICY_VIOLATION = 1006
    WALLET_FORMAT = 1007
    IPC_PROTOCOL = 1008
    PERMISSION_DENIED = 1009


_CODE_TO_CLASS: dict[int, type["SignerError"]] = {}


class SignerError(Exception):
    code: ErrorCode = ErrorCode.SIGNING  # default fallback

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if hasattr(cls, "code") and isinstance(cls.code, ErrorCode):
            _CODE_TO_CLASS[cls.code.value] = cls

    def to_dict(self) -> dict:
        return {"code": self.code.value, "message": str(self)}

    @classmethod
    def from_dict(cls, d: dict) -> "SignerError":
        code = d.get("code", 0)
        message = d.get("message", "unknown error")
        err_cls = _CODE_TO_CLASS.get(code, cls)
        return err_cls(message)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({str(self)!r})"


class SignerConnectionError(SignerError):
    """Client-side only — never serialized over IPC."""

    # Not registered in _CODE_TO_CLASS — this error is client-side only
    code = ErrorCode.SIGNING  # placeholder for consistency

    def __init_subclass__(cls, **kwargs):
        # Skip registration — this error never goes over the wire
        pass


class SignerLockedError(SignerError):
    code = ErrorCode.SIGNER_LOCKED


class SignerStateError(SignerError):
    code = ErrorCode.SIGNER_STATE


class InvalidPasswordError(SignerError):
    code = ErrorCode.INVALID_PASSWORD


class SigningError(SignerError):
    code = ErrorCode.SIGNING


class UnsupportedChainError(SignerError):
    code = ErrorCode.UNSUPPORTED_CHAIN


class PolicyViolationError(SignerError):
    code = ErrorCode.POLICY_VIOLATION


class WalletFormatError(SignerError):
    code = ErrorCode.WALLET_FORMAT


class IPCProtocolError(SignerError):
    code = ErrorCode.IPC_PROTOCOL


class PermissionDeniedError(SignerError):
    code = ErrorCode.PERMISSION_DENIED
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd "E:/OneDrive/00-personal-archive/crypto/crypto-signer" && python -m pytest tests/test_errors.py -v`
Expected: All 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/crypto_signer/errors.py tests/test_errors.py
git commit -m "feat: add error definitions and error code table"
```

---

### Task 3: Security — Zeroize

**Files:**
- Create: `src/crypto_signer/security/zeroize.py`
- Create: `tests/test_security.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_security.py
from crypto_signer.security.zeroize import zeroize, SecureByteArray


def test_zeroize_bytearray():
    buf = bytearray(b"secret_key_material")
    zeroize(buf)
    assert all(b == 0 for b in buf)
    assert len(buf) == 19


def test_zeroize_empty():
    buf = bytearray(b"")
    zeroize(buf)
    assert len(buf) == 0


def test_secure_bytearray_context_manager():
    with SecureByteArray(b"secret") as s:
        assert bytes(s) == b"secret"
    # after exit, should be zeroized
    assert all(b == 0 for b in s)


def test_secure_bytearray_repr_does_not_leak():
    s = SecureByteArray(b"private_key_data")
    r = repr(s)
    assert "private_key_data" not in r
    assert "SecureByteArray" in r


def test_secure_bytearray_str_does_not_leak():
    s = SecureByteArray(b"private_key_data")
    assert "private_key_data" not in str(s)


def test_secure_bytearray_del_zeroizes():
    s = SecureByteArray(b"secret")
    ref = s._data  # keep a reference to the underlying bytearray
    s.zeroize()
    assert all(b == 0 for b in ref)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_security.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write the implementation**

```python
# src/crypto_signer/security/zeroize.py
"""Secure memory zeroization utilities.

Provides best-effort zeroization for bytearray objects in Python.
Not a guarantee against all memory recovery — see SECURITY.md.
"""


def zeroize(buf: bytearray) -> None:
    """Overwrite every byte in buf with zeros."""
    for i in range(len(buf)):
        buf[i] = 0


class SecureByteArray:
    """A bytearray wrapper that zeroizes on cleanup.

    Usage:
        with SecureByteArray(b"secret") as s:
            do_something(s)
        # s is zeroized here
    """

    def __init__(self, data: bytes | bytearray = b""):
        if isinstance(data, bytearray):
            self._data = data
        else:
            self._data = bytearray(data)

    def __enter__(self) -> bytearray:
        return self._data

    def __exit__(self, *args) -> None:
        self.zeroize()

    def zeroize(self) -> None:
        zeroize(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __bytes__(self) -> bytes:
        return bytes(self._data)

    def __repr__(self) -> str:
        return f"SecureByteArray(len={len(self._data)})"

    def __str__(self) -> str:
        return f"SecureByteArray(len={len(self._data)})"

    def __del__(self) -> None:
        self.zeroize()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_security.py -v`
Expected: All 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/crypto_signer/security/zeroize.py tests/test_security.py
git commit -m "feat: add secure zeroization utilities"
```

---

### Task 4: Security — Platform Abstraction

**Files:**
- Create: `src/crypto_signer/security/platform.py`
- Create: `src/crypto_signer/security/platform_unix.py`
- Create: `src/crypto_signer/security/platform_win.py`
- Create: `tests/test_platform.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_platform.py
import sys

from crypto_signer.security.platform import (
    lock_memory,
    set_file_owner_only,
    harden_process,
    get_peer_credentials,
    PLATFORM,
)


def test_platform_detected():
    if sys.platform == "win32":
        assert PLATFORM == "windows"
    elif sys.platform == "darwin":
        assert PLATFORM == "macos"
    else:
        assert PLATFORM == "linux"


def test_lock_memory_returns_bool():
    # lock_memory may fail (not root, etc.) but must return bool
    buf = bytearray(64)
    result = lock_memory(buf)
    assert isinstance(result, bool)


def test_set_file_owner_only(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("data")
    # should not raise
    set_file_owner_only(str(f))


def test_harden_process_returns_dict():
    result = harden_process()
    assert isinstance(result, dict)
    assert "core_dump_disabled" in result
    assert "swap_warning" in result


def test_get_peer_credentials_returns_none_for_bad_socket():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = get_peer_credentials(s)
    s.close()
    assert result is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_platform.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write platform_unix.py**

```python
# src/crypto_signer/security/platform_unix.py
"""Unix/macOS platform security implementations."""

import ctypes
import ctypes.util
import logging
import os
import stat
import struct
import sys

logger = logging.getLogger(__name__)

PLATFORM = "macos" if sys.platform == "darwin" else "linux"


def lock_memory(buf: bytearray) -> bool:
    """Attempt to mlock a bytearray to prevent swapping."""
    try:
        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            return False
        libc = ctypes.CDLL(libc_name, use_errno=True)
        addr = (ctypes.c_char * len(buf)).from_buffer(buf)
        result = libc.mlock(ctypes.addressof(addr), len(buf))
        if result != 0:
            logger.warning("mlock failed: errno=%d", ctypes.get_errno())
            return False
        return True
    except Exception as e:
        logger.warning("mlock unavailable: %s", e)
        return False


def set_file_owner_only(path: str) -> None:
    """Set file permissions to 0600 (owner read/write only)."""
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def harden_process() -> dict:
    """Apply process-level security hardening."""
    result = {"core_dump_disabled": False, "swap_warning": False}

    # Disable core dumps
    try:
        if sys.platform == "linux":
            import ctypes
            PR_SET_DUMPABLE = 4
            libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
            libc.prctl(PR_SET_DUMPABLE, 0)
            result["core_dump_disabled"] = True
        elif sys.platform == "darwin":
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            result["core_dump_disabled"] = True
    except Exception as e:
        logger.warning("Could not disable core dumps: %s", e)

    # Check swap
    try:
        if sys.platform == "linux" and os.path.exists("/proc/swaps"):
            with open("/proc/swaps") as f:
                lines = f.readlines()
            if len(lines) > 1:  # header + at least one swap entry
                logger.warning("Swap is enabled. Private keys could be written to disk.")
                result["swap_warning"] = True
    except Exception as e:
        logger.warning("Could not check swap status: %s", e)

    return result


def get_peer_credentials(sock) -> int | None:
    """Get the UID of the peer connected to a Unix socket."""
    try:
        if sys.platform == "linux":
            SO_PEERCRED = 17
            cred = sock.getsockopt(
                __import__("socket").SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i")
            )
            pid, uid, gid = struct.unpack("3i", cred)
            return uid
        elif sys.platform == "darwin":
            LOCAL_PEERCRED = 0x001
            cred = sock.getsockopt(0, LOCAL_PEERCRED, struct.calcsize("iih16i"))
            uid = struct.unpack_from("iih", cred)[1]
            return uid
    except Exception:
        return None
    return None
```

- [ ] **Step 4: Write platform_win.py**

```python
# src/crypto_signer/security/platform_win.py
"""Windows platform security implementations."""

import ctypes
import logging
import os
import subprocess

logger = logging.getLogger(__name__)

PLATFORM = "windows"


def lock_memory(buf: bytearray) -> bool:
    """Attempt to VirtualLock a bytearray to prevent paging."""
    try:
        kernel32 = ctypes.windll.kernel32
        addr = (ctypes.c_char * len(buf)).from_buffer(buf)
        result = kernel32.VirtualLock(ctypes.addressof(addr), len(buf))
        if result == 0:
            logger.warning("VirtualLock failed: error=%d", ctypes.GetLastError())
            return False
        return True
    except Exception as e:
        logger.warning("VirtualLock unavailable: %s", e)
        return False


def set_file_owner_only(path: str) -> None:
    """Restrict file ACL to current user only."""
    try:
        # Try pywin32 first for reliable ACL management
        import win32security
        import ntsecuritycon as con

        user_sid = win32security.GetTokenInformation(
            win32security.OpenProcessToken(
                win32security.GetCurrentProcess(), con.TOKEN_QUERY
            ),
            win32security.TokenUser,
        )[0]

        dacl = win32security.ACL()
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION,
            con.FILE_ALL_ACCESS,
            user_sid,
        )
        sd = win32security.GetFileSecurity(
            path, win32security.DACL_SECURITY_INFORMATION
        )
        sd.SetSecurityDescriptorDacl(True, dacl, False)
        win32security.SetFileSecurity(
            path, win32security.DACL_SECURITY_INFORMATION, sd
        )
    except ImportError:
        # Fallback to icacls
        username = os.environ.get("USERNAME", "")
        if username:
            subprocess.run(
                ["icacls", path, "/inheritance:r", "/grant:r", f"{username}:(F)"],
                capture_output=True,
                check=False,
            )


def harden_process() -> dict:
    """Apply process-level security hardening (limited on Windows)."""
    result = {"core_dump_disabled": False, "swap_warning": True}

    logger.warning("Core dump protection not available on Windows")
    logger.warning(
        "Windows pagefile is always present. "
        "Private keys could be written to pagefile."
    )

    return result


def get_peer_credentials(sock) -> int | None:
    """Windows has no SO_PEERCRED equivalent."""
    logger.debug("Peer credential verification not available on Windows")
    return None
```

- [ ] **Step 5: Write platform.py dispatcher**

```python
# src/crypto_signer/security/platform.py
"""Platform detection and dispatch for security operations."""

import sys

if sys.platform == "win32":
    from .platform_win import (
        lock_memory,
        set_file_owner_only,
        harden_process,
        get_peer_credentials,
        PLATFORM,
    )
else:
    from .platform_unix import (
        lock_memory,
        set_file_owner_only,
        harden_process,
        get_peer_credentials,
        PLATFORM,
    )

__all__ = [
    "lock_memory",
    "set_file_owner_only",
    "harden_process",
    "get_peer_credentials",
    "PLATFORM",
]
```

- [ ] **Step 6: Run tests**

Run: `python -m pytest tests/test_platform.py -v`
Expected: All 5 tests PASS

- [ ] **Step 7: Commit**

```bash
git add src/crypto_signer/security/platform*.py tests/test_platform.py
git commit -m "feat: add cross-platform security abstraction"
```

---

### Task 5: Security — Harden & Safe Input

**Files:**
- Create: `src/crypto_signer/security/harden.py`
- Create: `src/crypto_signer/security/safe_input.py`

- [ ] **Step 1: Write harden.py**

```python
# src/crypto_signer/security/harden.py
"""High-level process hardening that delegates to platform module."""

import logging

from .platform import harden_process, lock_memory

logger = logging.getLogger(__name__)


def apply_hardening() -> dict:
    """Apply all available process hardening measures.

    Returns a dict summarizing what was applied.
    """
    result = harden_process()
    for key, value in result.items():
        if key == "core_dump_disabled" and value:
            logger.info("Core dump protection enabled")
        elif key == "swap_warning" and value:
            logger.warning("Swap/pagefile detected — keys may be paged to disk")
    return result


def lock_key_memory(buf: bytearray) -> bool:
    """Lock a key buffer in memory to prevent swapping."""
    success = lock_memory(buf)
    if success:
        logger.debug("Key memory locked successfully (%d bytes)", len(buf))
    else:
        logger.warning("Could not lock key memory — swap protection unavailable")
    return success
```

- [ ] **Step 2: Write safe_input.py**

```python
# src/crypto_signer/security/safe_input.py
"""Secure input utilities that return zeroizable bytearray."""

import getpass

from .zeroize import SecureByteArray


def secure_getpass(prompt: str = "Password: ") -> SecureByteArray:
    """Read a password from terminal without echo, returning a SecureByteArray.

    The caller is responsible for zeroizing the returned value when done.
    """
    raw = getpass.getpass(prompt)
    result = SecureByteArray(raw.encode("utf-8"))
    # Overwrite the Python str as best we can (imperfect — Python str is immutable)
    # At minimum we discard the reference immediately
    del raw
    return result
```

- [ ] **Step 3: Commit**

```bash
git add src/crypto_signer/security/harden.py src/crypto_signer/security/safe_input.py
git commit -m "feat: add process hardening and secure input"
```

---

### Task 6: Configuration

**Files:**
- Create: `src/crypto_signer/config.py`
- Create: `tests/test_config.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config.py
import os

from crypto_signer.config import Config, DEFAULT_CONFIG


def test_default_config():
    c = Config()
    assert c.socket_path.endswith("signer.sock")
    assert c.unlock_timeout == 0
    assert c.disable_core_dump is True
    assert c.try_mlock is True
    assert c.max_request_size == 1048576
    assert c.rate_limit == 60
    assert c.min_password_length == 8
    assert c.max_unlock_attempts == 5


def test_config_from_toml(tmp_path):
    toml_file = tmp_path / "config.toml"
    toml_file.write_text(
        '[signer]\n'
        'unlock_timeout = 3600\n'
        'try_mlock = false\n'
        '\n'
        '[security]\n'
        'rate_limit = 120\n'
    )
    c = Config.from_file(str(toml_file))
    assert c.unlock_timeout == 3600
    assert c.try_mlock is False
    assert c.rate_limit == 120
    # defaults preserved
    assert c.max_request_size == 1048576


def test_config_home_dir():
    c = Config()
    assert c.home_dir.endswith(".crypto-signer")


def test_config_missing_file_uses_defaults():
    c = Config.from_file("/nonexistent/path/config.toml")
    assert c.unlock_timeout == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_config.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write the implementation**

```python
# src/crypto_signer/config.py
"""Configuration loading for crypto-signer."""

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


def _default_home() -> str:
    return str(Path.home() / ".crypto-signer")


DEFAULT_CONFIG = {
    "signer": {
        "socket_path": "",  # computed from home_dir
        "unlock_timeout": 0,
        "disable_core_dump": True,
        "try_mlock": True,
    },
    "security": {
        "max_request_size": 1048576,
        "rate_limit": 60,
        "min_password_length": 8,
        "max_unlock_attempts": 5,
    },
}


@dataclass
class Config:
    home_dir: str = field(default_factory=_default_home)
    socket_path: str = ""
    unlock_timeout: int = 0
    disable_core_dump: bool = True
    try_mlock: bool = True
    max_request_size: int = 1048576
    rate_limit: int = 60
    min_password_length: int = 8
    max_unlock_attempts: int = 5

    def __post_init__(self):
        if not self.socket_path:
            self.socket_path = str(Path(self.home_dir) / "signer.sock")

    @property
    def keystore_path(self) -> str:
        return str(Path(self.home_dir) / "keystore.json")

    @property
    def pid_path(self) -> str:
        return str(Path(self.home_dir) / "signer.pid")

    @property
    def config_path(self) -> str:
        return str(Path(self.home_dir) / "config.toml")

    @classmethod
    def from_file(cls, path: str) -> "Config":
        """Load config from TOML file, falling back to defaults."""
        kwargs = {}
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except (FileNotFoundError, OSError):
            return cls()

        signer = data.get("signer", {})
        security = data.get("security", {})

        if "socket_path" in signer:
            kwargs["socket_path"] = signer["socket_path"]
        if "unlock_timeout" in signer:
            kwargs["unlock_timeout"] = signer["unlock_timeout"]
        if "disable_core_dump" in signer:
            kwargs["disable_core_dump"] = signer["disable_core_dump"]
        if "try_mlock" in signer:
            kwargs["try_mlock"] = signer["try_mlock"]
        if "max_request_size" in security:
            kwargs["max_request_size"] = security["max_request_size"]
        if "rate_limit" in security:
            kwargs["rate_limit"] = security["rate_limit"]
        if "min_password_length" in security:
            kwargs["min_password_length"] = security["min_password_length"]
        if "max_unlock_attempts" in security:
            kwargs["max_unlock_attempts"] = security["max_unlock_attempts"]

        return cls(**kwargs)

    @classmethod
    def load(cls, home_dir: str | None = None) -> "Config":
        """Load config from default location, optionally overriding home_dir."""
        if home_dir:
            config_path = str(Path(home_dir) / "config.toml")
            c = cls.from_file(config_path)
            c.home_dir = home_dir
            if not c.socket_path or c.socket_path.endswith("signer.sock"):
                c.socket_path = str(Path(home_dir) / "signer.sock")
            return c
        return cls.from_file(str(Path(_default_home()) / "config.toml"))
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_config.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/crypto_signer/config.py tests/test_config.py
git commit -m "feat: add TOML configuration loading"
```

---

## Chunk 2: Keystore & Crypto Engines

### Task 7: Keystore — Encrypt/Decrypt

**Files:**
- Create: `src/crypto_signer/keystore.py`
- Create: `tests/test_keystore.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_keystore.py
import json

from crypto_signer.keystore import Keystore, KeyEntry


def test_add_key_and_save(tmp_path):
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="test-evm",
        key_type="secp256k1",
        address="0xabcdef1234567890abcdef1234567890abcdef12",
        private_key=bytearray(b"\x01" * 32),
        password=bytearray(b"testpassword123"),
    )
    ks.save()

    # File should exist and be valid JSON
    data = json.loads(ks_path.read_text())
    assert data["version"] == 1
    assert data["kdf"] == "argon2id"
    assert len(data["keys"]) == 1
    assert data["keys"][0]["name"] == "test-evm"
    assert data["keys"][0]["key_type"] == "secp256k1"
    # encrypted_key should NOT be the raw key
    assert data["keys"][0]["encrypted_key"] != ""


def test_decrypt_key(tmp_path):
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    raw_key = bytearray(b"\xab" * 32)
    ks.add_key(
        name="test-evm",
        key_type="secp256k1",
        address="0x1234",
        private_key=bytearray(raw_key),  # copy
        password=bytearray(b"testpassword123"),
    )
    ks.save()

    # Load and decrypt
    ks2 = Keystore.load(str(ks_path))
    decrypted = ks2.decrypt_all(bytearray(b"testpassword123"))
    assert len(decrypted) == 1
    assert bytes(decrypted[0].private_key) == b"\xab" * 32


def test_decrypt_wrong_password(tmp_path):
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="test",
        key_type="secp256k1",
        address="0x1234",
        private_key=bytearray(b"\x01" * 32),
        password=bytearray(b"correct_password"),
    )
    ks.save()

    import pytest
    from crypto_signer.errors import InvalidPasswordError

    ks2 = Keystore.load(str(ks_path))
    with pytest.raises(InvalidPasswordError):
        ks2.decrypt_all(bytearray(b"wrong_password"))


def test_add_duplicate_chain_type_rejected(tmp_path):
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="evm-1",
        key_type="secp256k1",
        address="0x1111",
        private_key=bytearray(b"\x01" * 32),
        password=bytearray(b"testpassword123"),
    )

    import pytest
    with pytest.raises(ValueError, match="already exists"):
        ks.add_key(
            name="evm-2",
            key_type="secp256k1",
            address="0x2222",
            private_key=bytearray(b"\x02" * 32),
            password=bytearray(b"testpassword123"),
        )


def test_remove_key(tmp_path):
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="test",
        key_type="secp256k1",
        address="0x1234",
        private_key=bytearray(b"\x01" * 32),
        password=bytearray(b"testpassword123"),
    )
    ks.remove_key("test")
    assert len(ks.entries) == 0


def test_list_keys(tmp_path):
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="my-evm",
        key_type="secp256k1",
        address="0xabc",
        private_key=bytearray(b"\x01" * 32),
        password=bytearray(b"testpassword123"),
    )
    entries = ks.list_keys()
    assert len(entries) == 1
    assert entries[0] == {"name": "my-evm", "key_type": "secp256k1", "address": "0xabc"}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_keystore.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write the implementation**

```python
# src/crypto_signer/keystore.py
"""Encrypted keystore management.

Handles reading, writing, encrypting, and decrypting keystore.json.
All keys share one password. Each key has independent salt/IV.
"""

import base64
import json
import os
from dataclasses import dataclass

import argon2.low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import InvalidPasswordError, WalletFormatError
from .security.zeroize import SecureByteArray, zeroize

# Argon2id defaults (from spec)
_KDF_PARAMS = {
    "memory_cost": 65536,  # 64 MiB
    "time_cost": 3,
    "parallelism": 4,
}
_SALT_LEN = 16
_IV_LEN = 12
_KEY_LEN = 32  # AES-256


@dataclass
class KeyEntry:
    name: str
    key_type: str
    address: str
    # Only populated after decryption:
    private_key: bytearray | None = None


@dataclass
class _EncryptedEntry:
    name: str
    key_type: str
    address: str
    salt: bytes
    iv: bytes
    encrypted_key: bytes
    tag: bytes


def _derive_key(password: bytearray, salt: bytes) -> bytearray:
    """Derive a 32-byte key from password using Argon2id."""
    raw = argon2.low_level.hash_secret_raw(
        secret=bytes(password),
        salt=salt,
        time_cost=_KDF_PARAMS["time_cost"],
        memory_cost=_KDF_PARAMS["memory_cost"],
        parallelism=_KDF_PARAMS["parallelism"],
        hash_len=_KEY_LEN,
        type=argon2.low_level.Type.ID,
    )
    return bytearray(raw)


def _encrypt(private_key: bytearray, password: bytearray) -> tuple[bytes, bytes, bytes, bytes]:
    """Encrypt a private key. Returns (salt, iv, ciphertext, tag)."""
    salt = os.urandom(_SALT_LEN)
    iv = os.urandom(_IV_LEN)
    derived = _derive_key(password, salt)
    try:
        aes = AESGCM(bytes(derived))
        # AESGCM.encrypt appends the tag to the ciphertext
        ct_with_tag = aes.encrypt(iv, bytes(private_key), None)
        # Split: last 16 bytes are the GCM tag
        ct = ct_with_tag[:-16]
        tag = ct_with_tag[-16:]
        return salt, iv, ct, tag
    finally:
        zeroize(derived)


def _decrypt(
    salt: bytes, iv: bytes, ct: bytes, tag: bytes, password: bytearray
) -> bytearray:
    """Decrypt a private key. Returns bytearray."""
    derived = _derive_key(password, salt)
    try:
        aes = AESGCM(bytes(derived))
        ct_with_tag = ct + tag
        plaintext = aes.decrypt(iv, ct_with_tag, None)
        return bytearray(plaintext)
    except Exception:
        raise InvalidPasswordError("Decryption failed — wrong password or corrupted keystore")
    finally:
        zeroize(derived)


def _derive_address_from_key(key_type: str, private_key: bytearray) -> str:
    """Derive address from a private key for verification."""
    if key_type == "secp256k1":
        from .crypto.evm import EVMSigner
        signer = EVMSigner(bytearray(private_key))  # copy to avoid zeroizing original
        addr = signer.get_address()
        signer.zeroize()
        return addr
    elif key_type == "ed25519":
        from .crypto.solana import SolanaSigner
        signer = SolanaSigner(bytearray(private_key))
        addr = signer.get_address()
        signer.zeroize()
        return addr
    return ""


class Keystore:
    """Manages encrypted keystore file."""

    def __init__(self, path: str):
        self.path = path
        self.entries: list[_EncryptedEntry] = []

    def add_key(
        self,
        name: str,
        key_type: str,
        address: str,
        private_key: bytearray,
        password: bytearray,
    ) -> None:
        """Encrypt and add a key to the keystore."""
        # v1: one key per chain type
        chain_types = {"secp256k1": "evm", "ed25519": "solana"}
        chain = chain_types.get(key_type, key_type)
        for entry in self.entries:
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

    def remove_key(self, name: str) -> None:
        """Remove a key by name."""
        self.entries = [e for e in self.entries if e.name != name]

    def list_keys(self) -> list[dict]:
        """List keys (non-sensitive info only)."""
        return [
            {"name": e.name, "key_type": e.key_type, "address": e.address}
            for e in self.entries
        ]

    def decrypt_all(self, password: bytearray) -> list[KeyEntry]:
        """Decrypt all keys with the given password.

        Verifies each decrypted key's derived address matches the stored address.
        """
        results = []
        for entry in self.entries:
            pk = _decrypt(entry.salt, entry.iv, entry.encrypted_key, entry.tag, password)

            # Verify address matches (spec requirement)
            derived_addr = _derive_address_from_key(entry.key_type, pk)
            if derived_addr.lower() != entry.address.lower():
                zeroize(pk)
                raise WalletFormatError(
                    f"Address mismatch for key '{entry.name}': "
                    f"expected {entry.address}, derived {derived_addr}. "
                    "Keystore may be corrupted."
                )

            results.append(
                KeyEntry(
                    name=entry.name,
                    key_type=entry.key_type,
                    address=entry.address,
                    private_key=pk,
                )
            )
        return results

    def save(self) -> None:
        """Write keystore to disk as JSON with restricted permissions."""
        from .security.platform import set_file_owner_only

        data = {
            "version": 1,
            "kdf": "argon2id",
            "kdf_params": dict(_KDF_PARAMS),
            "keys": [
                {
                    "name": e.name,
                    "key_type": e.key_type,
                    "address": e.address,
                    "cipher": "aes-256-gcm",
                    "salt": base64.b64encode(e.salt).decode(),
                    "encrypted_key": base64.b64encode(e.encrypted_key).decode(),
                    "iv": base64.b64encode(e.iv).decode(),
                    "tag": base64.b64encode(e.tag).decode(),
                }
                for e in self.entries
            ],
        }
        with open(self.path, "w") as f:
            json.dump(data, f, indent=2)
        set_file_owner_only(self.path)

    @classmethod
    def load(cls, path: str) -> "Keystore":
        """Load keystore from disk."""
        try:
            with open(path) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            raise WalletFormatError(f"Cannot read keystore: {e}")

        if data.get("version") != 1:
            raise WalletFormatError(f"Unsupported keystore version: {data.get('version')}")

        ks = cls(path)
        for key_data in data.get("keys", []):
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
        return ks
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_keystore.py -v`
Expected: All 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/crypto_signer/keystore.py tests/test_keystore.py
git commit -m "feat: add encrypted keystore with Argon2id + AES-256-GCM"
```

---

### Task 8: EVM Signing Engine

**Files:**
- Create: `src/crypto_signer/crypto/evm.py`
- Create: `tests/test_crypto_evm.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_crypto_evm.py
import pytest

from crypto_signer.crypto.evm import EVMSigner


# Well-known test private key (DO NOT use in production)
TEST_KEY = bytearray(bytes.fromhex(
    "4c0883a69102937d6231471b5dbb6204fe512961708279f15b0d7e4b2cd53f37"
))
TEST_ADDRESS = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"


@pytest.fixture
def signer():
    return EVMSigner(bytearray(TEST_KEY))


def test_get_address(signer):
    addr = signer.get_address()
    assert addr.lower() == TEST_ADDRESS.lower()


def test_sign_transaction(signer):
    tx = {
        "to": "0x0000000000000000000000000000000000000000",
        "value": 0,
        "gas": 21000,
        "gasPrice": 1000000000,
        "nonce": 0,
        "chainId": 1,
    }
    result = signer.sign_transaction(tx)
    assert "signed_tx" in result
    assert "tx_hash" in result
    assert result["signed_tx"].startswith("0x")


def test_sign_message(signer):
    result = signer.sign_message("Hello World")
    assert "signature" in result
    assert result["signature"].startswith("0x")


def test_sign_typed_data(signer):
    domain = {
        "name": "Test",
        "version": "1",
        "chainId": 1,
    }
    types = {
        "Mail": [
            {"name": "contents", "type": "string"},
        ],
    }
    value = {"contents": "Hello"}
    result = signer.sign_typed_data(domain, types, value)
    assert "signature" in result
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_crypto_evm.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write the implementation**

```python
# src/crypto_signer/crypto/evm.py
"""EVM signing engine using eth-account."""

from eth_account import Account
from eth_account.messages import encode_defunct, encode_typed_data

from ..errors import SigningError


class EVMSigner:
    """Signs EVM transactions and messages using an in-memory private key."""

    def __init__(self, private_key: bytearray):
        self._key = private_key
        self._account = Account.from_key(bytes(private_key))

    def get_address(self) -> str:
        return self._account.address

    def sign_transaction(self, tx: dict) -> dict:
        """Sign an EVM transaction. Returns {"signed_tx": "0x...", "tx_hash": "0x..."}."""
        try:
            signed = self._account.sign_transaction(tx)
            return {
                "signed_tx": signed.raw_transaction.hex()
                if isinstance(signed.raw_transaction, bytes)
                else signed.raw_transaction,
                "tx_hash": signed.hash.hex()
                if isinstance(signed.hash, bytes)
                else signed.hash,
            }
        except Exception as e:
            raise SigningError(f"EVM sign_transaction failed: {e}")

    def sign_message(self, message: str) -> dict:
        """Sign a message (EIP-191). Returns {"signature": "0x..."}."""
        try:
            msg = encode_defunct(text=message)
            signed = self._account.sign_message(msg)
            sig_hex = signed.signature.hex() if isinstance(signed.signature, bytes) else signed.signature
            return {"signature": "0x" + sig_hex if not sig_hex.startswith("0x") else sig_hex}
        except Exception as e:
            raise SigningError(f"EVM sign_message failed: {e}")

    def sign_typed_data(self, domain: dict, types: dict, value: dict) -> dict:
        """Sign EIP-712 typed data. Returns {"signature": "0x..."}."""
        try:
            # encode_typed_data expects full_message style in newer versions
            msg = encode_typed_data(
                domain_data=domain,
                message_types=types,
                message_data=value,
            )
            signed = self._account.sign_message(msg)
            sig_hex = signed.signature.hex() if isinstance(signed.signature, bytes) else signed.signature
            return {"signature": "0x" + sig_hex if not sig_hex.startswith("0x") else sig_hex}
        except Exception as e:
            raise SigningError(f"EVM sign_typed_data failed: {e}")

    def zeroize(self) -> None:
        """Zeroize the private key from memory."""
        from ..security.zeroize import zeroize
        zeroize(self._key)
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_crypto_evm.py -v`
Expected: All 4 tests PASS (sign_typed_data may need adjustment depending on eth-account version — adapt encode_typed_data call if needed)

- [ ] **Step 5: Commit**

```bash
git add src/crypto_signer/crypto/evm.py tests/test_crypto_evm.py
git commit -m "feat: add EVM signing engine"
```

---

### Task 9: Solana Signing Engine

**Files:**
- Create: `src/crypto_signer/crypto/solana.py`
- Create: `tests/test_crypto_solana.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_crypto_solana.py
import base64

import pytest
from solders.keypair import Keypair
from solders.message import Message
from solders.transaction import Transaction
from solders.system_program import transfer, TransferParams
from solders.pubkey import Pubkey
from solders.hash import Hash

from crypto_signer.crypto.solana import SolanaSigner


@pytest.fixture
def keypair():
    return Keypair()


@pytest.fixture
def signer(keypair):
    raw = bytes(keypair)
    return SolanaSigner(bytearray(raw))


def test_get_address(signer, keypair):
    addr = signer.get_address()
    assert addr == str(keypair.pubkey())


def test_sign_transaction(signer, keypair):
    # Build a simple transfer instruction
    ix = transfer(
        TransferParams(
            from_pubkey=keypair.pubkey(),
            to_pubkey=Pubkey.default(),
            lamports=1000,
        )
    )
    msg = Message.new_with_blockhash(
        [ix], keypair.pubkey(), Hash.default()
    )
    tx = Transaction.new_unsigned(msg)
    tx_bytes = bytes(tx)
    tx_b64 = base64.b64encode(tx_bytes).decode()

    result = signer.sign_transaction(tx_b64)
    assert "signed_tx" in result
    # signed_tx is base64
    decoded = base64.b64decode(result["signed_tx"])
    assert len(decoded) > 0


def test_sign_message(signer):
    msg = base64.b64encode(b"Hello Solana").decode()
    result = signer.sign_message(msg)
    assert "signature" in result
    sig_bytes = base64.b64decode(result["signature"])
    assert len(sig_bytes) == 64  # Ed25519 signature
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_crypto_solana.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write the implementation**

```python
# src/crypto_signer/crypto/solana.py
"""Solana signing engine using solders."""

import base64

from solders.keypair import Keypair
from solders.transaction import Transaction

from ..errors import SigningError


class SolanaSigner:
    """Signs Solana transactions and messages using an in-memory private key."""

    def __init__(self, private_key: bytearray):
        self._key = private_key
        try:
            if len(private_key) == 32:
                # 32-byte Ed25519 seed (e.g., from mnemonic derivation)
                self._keypair = Keypair.from_seed(bytes(private_key))
            elif len(private_key) == 64:
                # 64-byte keypair (32-byte seed + 32-byte public key)
                self._keypair = Keypair.from_bytes(bytes(private_key))
            else:
                raise SigningError(
                    f"Invalid Solana key length: {len(private_key)}. Expected 32 or 64 bytes."
                )
        except SigningError:
            raise
        except Exception as e:
            raise SigningError(f"Invalid Solana private key: {e}")

    def get_address(self) -> str:
        return str(self._keypair.pubkey())

    def sign_transaction(self, tx_b64: str) -> dict:
        """Sign a serialized Solana transaction (base64).

        Returns {"signed_tx": "<base64>"}.
        """
        try:
            tx_bytes = base64.b64decode(tx_b64)
            tx = Transaction.from_bytes(tx_bytes)
            tx.sign([self._keypair], tx.message.recent_blockhash)
            signed_bytes = bytes(tx)
            return {"signed_tx": base64.b64encode(signed_bytes).decode()}
        except Exception as e:
            raise SigningError(f"Solana sign_transaction failed: {e}")

    def sign_message(self, message_b64: str) -> dict:
        """Sign a raw message (base64).

        Returns {"signature": "<base64>"}.
        """
        try:
            msg_bytes = base64.b64decode(message_b64)
            sig = self._keypair.sign_message(msg_bytes)
            return {"signature": base64.b64encode(bytes(sig)).decode()}
        except Exception as e:
            raise SigningError(f"Solana sign_message failed: {e}")

    def zeroize(self) -> None:
        """Zeroize the private key from memory."""
        from ..security.zeroize import zeroize
        zeroize(self._key)
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_crypto_solana.py -v`
Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/crypto_signer/crypto/solana.py tests/test_crypto_solana.py
git commit -m "feat: add Solana signing engine"
```

---

## Chunk 3: State Machine & Server

### Task 10: State Machine

**Files:**
- Create: `src/crypto_signer/state.py`
- Create: `tests/test_state.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_state.py
import pytest

from crypto_signer.state import SignerState, SignerStateMachine
from crypto_signer.errors import SignerLockedError, SignerStateError


def test_initial_state():
    sm = SignerStateMachine()
    assert sm.state == SignerState.INIT


def test_init_to_locked():
    sm = SignerStateMachine()
    sm.transition_to(SignerState.LOCKED)
    assert sm.state == SignerState.LOCKED


def test_locked_to_unlocked():
    sm = SignerStateMachine()
    sm.transition_to(SignerState.LOCKED)
    sm.transition_to(SignerState.UNLOCKED)
    assert sm.state == SignerState.UNLOCKED


def test_unlocked_to_locked():
    sm = SignerStateMachine()
    sm.transition_to(SignerState.LOCKED)
    sm.transition_to(SignerState.UNLOCKED)
    sm.transition_to(SignerState.LOCKED)
    assert sm.state == SignerState.LOCKED


def test_unlocked_to_stopped():
    sm = SignerStateMachine()
    sm.transition_to(SignerState.LOCKED)
    sm.transition_to(SignerState.UNLOCKED)
    sm.transition_to(SignerState.STOPPED)
    assert sm.state == SignerState.STOPPED


def test_invalid_transition_raises():
    sm = SignerStateMachine()
    with pytest.raises(SignerStateError):
        sm.transition_to(SignerState.UNLOCKED)  # can't go INIT -> UNLOCKED


def test_error_to_locked():
    sm = SignerStateMachine()
    sm.transition_to(SignerState.LOCKED)
    sm.transition_to(SignerState.ERROR)
    sm.transition_to(SignerState.LOCKED)
    assert sm.state == SignerState.LOCKED


def test_any_to_error():
    sm = SignerStateMachine()
    sm.transition_to(SignerState.LOCKED)
    sm.transition_to(SignerState.UNLOCKED)
    sm.transition_to(SignerState.ERROR)
    assert sm.state == SignerState.ERROR


def test_require_unlocked():
    sm = SignerStateMachine()
    sm.transition_to(SignerState.LOCKED)
    with pytest.raises(SignerLockedError):
        sm.require_unlocked()
    sm.transition_to(SignerState.UNLOCKED)
    sm.require_unlocked()  # should not raise
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_state.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write the implementation**

```python
# src/crypto_signer/state.py
"""Signer state machine.

States: INIT -> LOCKED -> UNLOCKED -> STOPPED
                 ^           |
                 |   lock/TTL|
                 +-----------+
        Any -> ERROR -> LOCKED | STOPPED
"""

from enum import Enum

from .errors import SignerLockedError, SignerStateError


class SignerState(Enum):
    INIT = "init"
    LOCKED = "locked"
    UNLOCKED = "unlocked"
    ERROR = "error"
    STOPPED = "stopped"


# Valid transitions: {from_state: {allowed_to_states}}
_TRANSITIONS: dict[SignerState, set[SignerState]] = {
    SignerState.INIT: {SignerState.LOCKED, SignerState.ERROR, SignerState.STOPPED},
    SignerState.LOCKED: {SignerState.UNLOCKED, SignerState.ERROR, SignerState.STOPPED},
    SignerState.UNLOCKED: {SignerState.LOCKED, SignerState.ERROR, SignerState.STOPPED},
    SignerState.ERROR: {SignerState.LOCKED, SignerState.STOPPED},
    SignerState.STOPPED: set(),  # terminal
}


class SignerStateMachine:
    def __init__(self):
        self._state = SignerState.INIT

    @property
    def state(self) -> SignerState:
        return self._state

    def transition_to(self, new_state: SignerState) -> None:
        allowed = _TRANSITIONS.get(self._state, set())
        if new_state not in allowed:
            raise SignerStateError(
                f"Invalid transition: {self._state.value} -> {new_state.value}"
            )
        self._state = new_state

    def require_unlocked(self) -> None:
        if self._state != SignerState.UNLOCKED:
            raise SignerLockedError("Signer is locked")
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_state.py -v`
Expected: All 9 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/crypto_signer/state.py tests/test_state.py
git commit -m "feat: add signer state machine"
```

---

### Task 11: IPC Server

**Files:**
- Create: `src/crypto_signer/server.py`
- Create: `tests/test_server.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_server.py
import json
import os
import socket
import threading
import time

import pytest

from crypto_signer.server import SignerServer
from crypto_signer.config import Config
from crypto_signer.keystore import Keystore


def _send_request(sock_path: str, request: dict) -> dict:
    """Helper: send a JSON request to the server and return the response."""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sock_path)
    s.sendall((json.dumps(request) + "\n").encode())
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
        if b"\n" in data:
            break
    s.close()
    return json.loads(data.decode().strip())


@pytest.fixture
def server_env(tmp_path):
    """Set up a keystore + config + server."""
    home = tmp_path / ".crypto-signer"
    home.mkdir()
    ks_path = home / "keystore.json"
    sock_path = str(home / "signer.sock")

    # Create a keystore with a test EVM key
    ks = Keystore(str(ks_path))
    test_key = bytearray(bytes.fromhex(
        "4c0883a69102937d6231471b5dbb6204fe512961708279f15b0d7e4b2cd53f37"
    ))
    ks.add_key(
        name="test-evm",
        key_type="secp256k1",
        address="0x2c7536E3605D9C16a7a3D7b1898e529396a65c23",
        private_key=test_key,
        password=bytearray(b"testpass1234"),
    )
    ks.save()

    config = Config(
        home_dir=str(home),
        socket_path=sock_path,
        rate_limit=1000,  # high limit for tests
    )
    return config, str(ks_path), sock_path


@pytest.fixture
def running_server(server_env):
    config, ks_path, sock_path = server_env
    server = SignerServer(config)
    server.load_keystore()

    t = threading.Thread(target=server.serve, daemon=True)
    t.start()
    # Wait for socket to appear
    for _ in range(50):
        if os.path.exists(sock_path):
            break
        time.sleep(0.05)

    yield server, sock_path

    server.shutdown()


def test_ping(running_server):
    server, sock_path = running_server
    resp = _send_request(sock_path, {
        "version": 1, "id": "1", "method": "ping", "params": {}
    })
    assert resp["id"] == "1"
    assert resp["result"]["status"] == "ok"


def test_status_when_locked(running_server):
    server, sock_path = running_server
    resp = _send_request(sock_path, {
        "version": 1, "id": "2", "method": "status", "params": {}
    })
    assert resp["result"]["state"] == "locked"


def test_unlock_and_sign(running_server):
    server, sock_path = running_server
    # Unlock
    resp = _send_request(sock_path, {
        "version": 1, "id": "3", "method": "unlock",
        "params": {"password": "testpass1234"}
    })
    assert "result" in resp

    # Status should be unlocked
    resp = _send_request(sock_path, {
        "version": 1, "id": "4", "method": "status", "params": {}
    })
    assert resp["result"]["state"] == "unlocked"

    # Sign a transaction
    resp = _send_request(sock_path, {
        "version": 1, "id": "5", "method": "sign_transaction",
        "params": {
            "chain": "evm",
            "tx": {
                "to": "0x0000000000000000000000000000000000000000",
                "value": 0,
                "gas": 21000,
                "gasPrice": 1000000000,
                "nonce": 0,
                "chainId": 1,
            }
        }
    })
    assert "result" in resp
    assert "signed_tx" in resp["result"]


def test_sign_when_locked_returns_error(running_server):
    server, sock_path = running_server
    resp = _send_request(sock_path, {
        "version": 1, "id": "6", "method": "sign_transaction",
        "params": {"chain": "evm", "tx": {}}
    })
    assert "error" in resp
    assert resp["error"]["code"] == 1001  # SignerLockedError


def test_lock_after_unlock(running_server):
    server, sock_path = running_server
    # Unlock
    _send_request(sock_path, {
        "version": 1, "id": "7", "method": "unlock",
        "params": {"password": "testpass1234"}
    })
    # Lock
    resp = _send_request(sock_path, {
        "version": 1, "id": "8", "method": "lock", "params": {}
    })
    assert "result" in resp

    # Status should be locked again
    resp = _send_request(sock_path, {
        "version": 1, "id": "9", "method": "status", "params": {}
    })
    assert resp["result"]["state"] == "locked"


def test_invalid_method(running_server):
    server, sock_path = running_server
    resp = _send_request(sock_path, {
        "version": 1, "id": "10", "method": "nonexistent", "params": {}
    })
    assert "error" in resp
    assert resp["error"]["code"] == 1008  # IPCProtocolError
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_server.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write the implementation**

```python
# src/crypto_signer/server.py
"""Unix domain socket signing server."""

import json
import logging
import os
import socket
import threading
import time

from .config import Config
from .errors import (
    ErrorCode,
    IPCProtocolError,
    InvalidPasswordError,
    PolicyViolationError,
    SignerError,
    SignerLockedError,
    SignerStateError,
    UnsupportedChainError,
)
from .keystore import Keystore, KeyEntry
from .crypto.evm import EVMSigner
from .crypto.solana import SolanaSigner
from .security.harden import apply_hardening, lock_key_memory
from .security.platform import set_file_owner_only
from .security.zeroize import zeroize
from .state import SignerState, SignerStateMachine

logger = logging.getLogger(__name__)

_MAX_MSG = 1048576  # 1 MB default


class SignerServer:
    def __init__(self, config: Config):
        self.config = config
        self._sm = SignerStateMachine()
        self._keystore: Keystore | None = None
        self._evm: EVMSigner | None = None
        self._solana: SolanaSigner | None = None
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
                elif key.key_type == "ed25519":
                    self._solana = SolanaSigner(key.private_key)

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
            if self._solana:
                self._solana.zeroize()
                self._solana = None
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
                raise IPCProtocolError("Request too large")
            request = json.loads(text)
        except (json.JSONDecodeError, UnicodeDecodeError):
            err = IPCProtocolError("Invalid JSON")
            return (json.dumps({"id": None, "error": err.to_dict()}) + "\n").encode()

        req_id = request.get("id")
        version = request.get("version")
        if version != 1:
            err = IPCProtocolError(f"Unsupported protocol version: {version}")
            return (json.dumps({"id": req_id, "error": err.to_dict()}) + "\n").encode()

        method = request.get("method", "")
        params = request.get("params", {})

        try:
            result = self._dispatch(method, params)
            return (json.dumps({"id": req_id, "result": result}) + "\n").encode()
        except SignerError as e:
            return (json.dumps({"id": req_id, "error": e.to_dict()}) + "\n").encode()

    def _dispatch(self, method: str, params: dict) -> dict:
        handlers = {
            "ping": self._handle_ping,
            "status": self._handle_status,
            "unlock": self._handle_unlock,
            "lock": self._handle_lock,
            "shutdown": self._handle_shutdown,
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
        elif chain == "solana":
            if self._solana is None:
                raise UnsupportedChainError("No Solana key loaded")
            return self._solana
        raise UnsupportedChainError(f"Unsupported chain: {chain}")

    def _handle_get_address(self, params: dict) -> dict:
        chain = params.get("chain", "")
        signer = self._get_chain_signer(chain)
        return {"address": signer.get_address()}

    def _handle_sign_transaction(self, params: dict) -> dict:
        self._check_rate_limit()
        chain = params.get("chain", "")
        signer = self._get_chain_signer(chain)
        if chain == "evm":
            return signer.sign_transaction(params.get("tx", {}))
        else:
            return signer.sign_transaction(params.get("tx", ""))

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
        """Start serving on Unix domain socket."""
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
        sock_path = self.config.socket_path
        if os.path.exists(sock_path):
            os.unlink(sock_path)
        try:
            self._sm.transition_to(SignerState.STOPPED)
        except SignerStateError:
            pass
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_server.py -v`
Expected: All 6 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/crypto_signer/server.py tests/test_server.py
git commit -m "feat: add Unix socket signing server with state machine"
```

---

## Chunk 4: Client Library

### Task 12: SignerClient

**Files:**
- Create: `src/crypto_signer/client.py`
- Create: `tests/test_client.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_client.py
import json
import os
import socket
import threading
import time

import pytest

from crypto_signer.client import SignerClient
from crypto_signer.errors import SignerLockedError, SignerConnectionError


@pytest.fixture
def mock_server(tmp_path):
    """A minimal mock server that responds to IPC requests."""
    sock_path = str(tmp_path / "test.sock")
    responses = {}

    def set_response(method, result=None, error=None):
        responses[method] = (result, error)

    def server_loop():
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(sock_path)
        srv.listen(5)
        srv.settimeout(1.0)

        while getattr(server_loop, "running", True):
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue

            data = conn.recv(4096)
            req = json.loads(data.decode().strip())
            method = req.get("method", "")
            req_id = req.get("id")

            result, error = responses.get(method, ({"status": "ok"}, None))
            if error:
                resp = {"id": req_id, "error": error}
            else:
                resp = {"id": req_id, "result": result}

            conn.sendall((json.dumps(resp) + "\n").encode())
            conn.close()

        srv.close()
        if os.path.exists(sock_path):
            os.unlink(sock_path)

    server_loop.running = True
    t = threading.Thread(target=server_loop, daemon=True)
    t.start()

    for _ in range(50):
        if os.path.exists(sock_path):
            break
        time.sleep(0.05)

    yield sock_path, set_response

    server_loop.running = False
    t.join(timeout=3)


def test_ping(mock_server):
    sock_path, set_response = mock_server
    set_response("ping", {"status": "ok"})
    client = SignerClient(socket_path=sock_path)
    result = client.ping()
    assert result["status"] == "ok"


def test_status(mock_server):
    sock_path, set_response = mock_server
    set_response("status", {"state": "locked", "uptime": 42})
    client = SignerClient(socket_path=sock_path)
    result = client.status()
    assert result["state"] == "locked"


def test_evm_get_address(mock_server):
    sock_path, set_response = mock_server
    set_response("get_address", {"address": "0x1234"})
    client = SignerClient(socket_path=sock_path)
    addr = client.evm.get_address()
    assert addr == "0x1234"


def test_evm_sign_transaction(mock_server):
    sock_path, set_response = mock_server
    set_response("sign_transaction", {"signed_tx": "0xabc", "tx_hash": "0xdef"})
    client = SignerClient(socket_path=sock_path)
    result = client.evm.sign_transaction({"to": "0x0", "value": 0})
    assert result["signed_tx"] == "0xabc"


def test_solana_get_address(mock_server):
    sock_path, set_response = mock_server
    set_response("get_address", {"address": "SoL123"})
    client = SignerClient(socket_path=sock_path)
    addr = client.solana.get_address()
    assert addr == "SoL123"


def test_error_response_raises(mock_server):
    sock_path, set_response = mock_server
    set_response("sign_transaction", error={"code": 1001, "message": "locked"})
    client = SignerClient(socket_path=sock_path)
    with pytest.raises(SignerLockedError):
        client.evm.sign_transaction({})


def test_connection_error():
    client = SignerClient(socket_path="/nonexistent/path.sock")
    with pytest.raises(SignerConnectionError):
        client.ping()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_client.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write the implementation**

```python
# src/crypto_signer/client.py
"""SignerClient — Python client for the crypto-signer daemon."""

import json
import socket
import uuid
from pathlib import Path

from .errors import SignerError, SignerConnectionError


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
    """Client for communicating with the crypto-signer daemon."""

    def __init__(self, socket_path: str | None = None):
        self._socket_path = socket_path or _default_socket_path()
        self.evm = _ChainClient(self._send, "evm")
        self.solana = _ChainClient(self._send, "solana")

    def _send(self, method: str, params: dict | None = None) -> dict:
        request = {
            "version": 1,
            "id": str(uuid.uuid4())[:8],
            "method": method,
            "params": params or {},
        }
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(30.0)
            s.connect(self._socket_path)
            s.sendall((json.dumps(request) + "\n").encode())

            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break
            s.close()
        except (ConnectionRefusedError, FileNotFoundError, OSError) as e:
            raise SignerConnectionError(f"Cannot connect to signer: {e}")

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
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_client.py -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/crypto_signer/client.py tests/test_client.py
git commit -m "feat: add SignerClient with chain-specific sub-clients"
```

---

### Task 13: Public API (__init__.py)

**Files:**
- Modify: `src/crypto_signer/__init__.py`

- [ ] **Step 1: Write the public API**

```python
# src/crypto_signer/__init__.py
"""crypto-signer: Encrypted wallet + memory-resident signing service."""

from .client import SignerClient
from .errors import (
    SignerError,
    SignerConnectionError,
    SignerLockedError,
    SignerStateError,
    InvalidPasswordError,
    SigningError,
    UnsupportedChainError,
    PolicyViolationError,
    WalletFormatError,
    IPCProtocolError,
    PermissionDeniedError,
)

__all__ = [
    "SignerClient",
    "SignerError",
    "SignerConnectionError",
    "SignerLockedError",
    "SignerStateError",
    "InvalidPasswordError",
    "SigningError",
    "UnsupportedChainError",
    "PolicyViolationError",
    "WalletFormatError",
    "IPCProtocolError",
    "PermissionDeniedError",
]
```

- [ ] **Step 2: Commit**

```bash
git add src/crypto_signer/__init__.py
git commit -m "feat: export public API from package"
```

---

## Chunk 5: CLI

### Task 14: CLI Commands

**Files:**
- Create: `src/crypto_signer/cli.py`
- Create: `tests/test_cli.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli.py
import json

import pytest
from click.testing import CliRunner

from crypto_signer.cli import main


@pytest.fixture
def runner():
    return CliRunner()


def test_init_creates_directory(runner, tmp_path):
    home = str(tmp_path / ".crypto-signer")
    result = runner.invoke(main, ["init", "--home", home])
    assert result.exit_code == 0
    assert (tmp_path / ".crypto-signer").exists()
    assert (tmp_path / ".crypto-signer" / "config.toml").exists()


def test_list_empty(runner, tmp_path):
    home = str(tmp_path / ".crypto-signer")
    (tmp_path / ".crypto-signer").mkdir()
    ks_path = tmp_path / ".crypto-signer" / "keystore.json"
    ks_path.write_text(json.dumps({"version": 1, "kdf": "argon2id", "kdf_params": {}, "keys": []}))

    result = runner.invoke(main, ["list", "--home", home])
    assert result.exit_code == 0
    assert "No keys" in result.output


def test_add_key_interactive(runner, tmp_path):
    home = str(tmp_path / ".crypto-signer")
    (tmp_path / ".crypto-signer").mkdir()
    ks_path = tmp_path / ".crypto-signer" / "keystore.json"
    ks_path.write_text(json.dumps({"version": 1, "kdf": "argon2id", "kdf_params": {}, "keys": []}))

    # Simulate interactive input: private key + password + confirm
    test_key = "4c0883a69102937d6231471b5dbb6204fe512961708279f15b0d7e4b2cd53f37"
    input_text = f"{test_key}\ntestpass1234\ntestpass1234\n"

    result = runner.invoke(
        main,
        ["add", "--name", "test-evm", "--type", "evm", "--key", "--home", home],
        input=input_text,
    )
    assert result.exit_code == 0

    # Verify keystore has the key
    data = json.loads(ks_path.read_text())
    assert len(data["keys"]) == 1
    assert data["keys"][0]["name"] == "test-evm"


def test_remove_key(runner, tmp_path):
    home = str(tmp_path / ".crypto-signer")
    (tmp_path / ".crypto-signer").mkdir()
    ks_path = tmp_path / ".crypto-signer" / "keystore.json"
    ks_path.write_text(json.dumps({"version": 1, "kdf": "argon2id", "kdf_params": {}, "keys": []}))

    # Add a key first
    test_key = "4c0883a69102937d6231471b5dbb6204fe512961708279f15b0d7e4b2cd53f37"
    runner.invoke(
        main,
        ["add", "--name", "test-evm", "--type", "evm", "--key", "--home", home],
        input=f"{test_key}\ntestpass1234\ntestpass1234\n",
    )

    # Remove it
    result = runner.invoke(main, ["remove", "--name", "test-evm", "--home", home])
    assert result.exit_code == 0

    data = json.loads(ks_path.read_text())
    assert len(data["keys"]) == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write the implementation**

```python
# src/crypto_signer/cli.py
"""CLI entry point for crypto-signer."""

import json
import logging
import os
import signal
import sys
import threading

import click

from .config import Config
from .errors import WalletFormatError
from .keystore import Keystore
from .security.zeroize import zeroize


def _get_config(home: str | None) -> Config:
    if home:
        return Config.load(home_dir=home)
    return Config.load()


def _get_or_create_keystore(config: Config) -> Keystore:
    try:
        return Keystore.load(config.keystore_path)
    except (WalletFormatError, FileNotFoundError):
        return Keystore(config.keystore_path)


def _derive_address(key_type: str, private_key: bytearray) -> str:
    """Derive address from private key for verification."""
    if key_type in ("evm", "secp256k1"):
        from .crypto.evm import EVMSigner
        signer = EVMSigner(bytearray(private_key))  # copy
        addr = signer.get_address()
        signer.zeroize()
        return addr
    elif key_type in ("solana", "ed25519"):
        from .crypto.solana import SolanaSigner
        signer = SolanaSigner(bytearray(private_key))  # copy
        addr = signer.get_address()
        signer.zeroize()
        return addr
    raise click.ClickException(f"Unsupported type: {key_type}")


_TYPE_MAP = {"evm": "secp256k1", "solana": "ed25519"}


@click.group()
def main():
    """crypto-signer: Encrypted wallet + memory-resident signing service."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


@main.command()
@click.option("--home", default=None, help="Override home directory")
def init(home):
    """Initialize ~/.crypto-signer/ directory."""
    config = _get_config(home)
    os.makedirs(config.home_dir, exist_ok=True)

    # Create default config.toml if it doesn't exist
    config_path = config.config_path
    if not os.path.exists(config_path):
        with open(config_path, "w") as f:
            f.write(
                "[signer]\n"
                "# socket_path = \"~/.crypto-signer/signer.sock\"\n"
                "# unlock_timeout = 0\n"
                "# disable_core_dump = true\n"
                "# try_mlock = true\n"
                "\n"
                "[security]\n"
                "# max_request_size = 1048576\n"
                "# rate_limit = 60\n"
                "# min_password_length = 8\n"
                "# max_unlock_attempts = 5\n"
            )

    # Create empty keystore if it doesn't exist
    if not os.path.exists(config.keystore_path):
        ks = Keystore(config.keystore_path)
        ks.save()

    click.echo(f"Initialized {config.home_dir}")


@main.command()
@click.option("--name", required=True, help="Key name")
@click.option("--type", "key_type", required=True, type=click.Choice(["evm", "solana"]))
@click.option("--key", "import_key", is_flag=True, help="Import private key")
@click.option("--mnemonic", "import_mnemonic", is_flag=True, help="Import from mnemonic")
@click.option("--home", default=None, help="Override home directory")
def add(name, key_type, import_key, import_mnemonic, home):
    """Add a key to the keystore."""
    if not import_key and not import_mnemonic:
        raise click.ClickException("Specify --key or --mnemonic")

    config = _get_config(home)
    ks = _get_or_create_keystore(config)
    internal_type = _TYPE_MAP[key_type]

    if import_key:
        raw_hex = click.prompt("Enter private key", hide_input=True)
        raw_bytes = bytearray(bytes.fromhex(raw_hex.strip().removeprefix("0x")))
    else:
        # Mnemonic import
        mnemonic = click.prompt("Enter mnemonic phrase", hide_input=True)
        raw_bytes = _derive_from_mnemonic(mnemonic, key_type)
        del mnemonic

    address = _derive_address(key_type, raw_bytes)

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

    click.echo(f"Key '{name}' added. Address: {address}")


def _derive_from_mnemonic(mnemonic: str, key_type: str) -> bytearray:
    """Derive a private key from a mnemonic phrase using BIP-44 paths.

    EVM: m/44'/60'/0'/0/0
    Solana: m/44'/501'/0'/0'
    """
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
    except Exception as e:
        raise click.ClickException(f"Mnemonic derivation failed: {e}")


@main.command("list")
@click.option("--home", default=None, help="Override home directory")
def list_keys(home):
    """List stored keys."""
    config = _get_config(home)
    try:
        ks = Keystore.load(config.keystore_path)
    except WalletFormatError:
        click.echo("No keystore found. Run 'crypto-signer init' first.")
        return

    keys = ks.list_keys()
    if not keys:
        click.echo("No keys stored.")
        return

    for k in keys:
        chain = "evm" if k["key_type"] == "secp256k1" else "solana"
        click.echo(f"  {k['name']}  [{chain}]  {k['address']}")


@main.command()
@click.option("--name", required=True, help="Key name to remove")
@click.option("--home", default=None, help="Override home directory")
def remove(name, home):
    """Remove a key from the keystore."""
    config = _get_config(home)
    ks = Keystore.load(config.keystore_path)
    ks.remove_key(name)
    ks.save()
    click.echo(f"Key '{name}' removed.")


@main.command()
@click.option("-d", "daemon", is_flag=True, help="Run in background")
@click.option("--home", default=None, help="Override home directory")
def start(daemon, home):
    """Start the signing service."""
    from .server import SignerServer
    from .security.harden import apply_hardening

    config = _get_config(home)
    server = SignerServer(config)
    server.load_keystore()

    # Prompt for password
    password_str = click.prompt("Enter password to unlock", hide_input=True)
    password = bytearray(password_str.encode("utf-8"))
    del password_str

    try:
        server.unlock(password, config.unlock_timeout)
    except Exception as e:
        raise click.ClickException(str(e))

    click.echo("Signer unlocked and ready.")

    if daemon:
        if sys.platform == "win32":
            _start_daemon_windows(server, config)
            return
        else:
            _start_daemon_unix(server, config)
            return

    # Foreground mode
    apply_hardening()

    def _signal_handler(sig, frame):
        click.echo("\nShutting down...")
        server.shutdown()

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    server.serve()


def _start_daemon_unix(server, config):
    """Fork to background on Unix.

    After fork, the child inherits the already-unlocked server.
    The parent must zeroize its copy of keys before returning.
    """
    pid = os.fork()
    if pid > 0:
        # Parent: write PID and clean up our copy of decrypted keys
        with open(config.pid_path, "w") as f:
            f.write(str(pid))
        server.lock()  # zeroize parent's copy of keys
        click.echo(f"Daemon started (PID {pid})")
        return
    # Child process
    os.setsid()
    from .security.harden import apply_hardening
    apply_hardening()
    server.serve()


def _start_daemon_windows(server, config):
    """Start daemon on Windows.

    Windows has no fork(). Since keys are already decrypted in this process,
    we start the server in a background thread and let the main thread exit.
    The process stays alive because the server thread is non-daemon.

    Note: On Windows, -d mode will detach from the terminal but the process
    remains in the task list. Use 'crypto-signer stop' to shut down.
    """
    from .security.harden import apply_hardening
    apply_hardening()

    # Write PID file for stop command
    with open(config.pid_path, "w") as f:
        f.write(str(os.getpid()))

    click.echo(f"Daemon started (PID {os.getpid()})")

    # Run server in a non-daemon thread so process stays alive
    t = threading.Thread(target=server.serve, daemon=False)
    t.start()

    # Free the console (Windows-specific)
    try:
        import ctypes
        ctypes.windll.kernel32.FreeConsole()
    except Exception:
        pass

    t.join()  # block until server shuts down


@main.command()
@click.option("--home", default=None, help="Override home directory")
def stop(home):
    """Stop the signing service."""
    from .client import SignerClient
    config = _get_config(home)
    try:
        client = SignerClient(socket_path=config.socket_path)
        client._send("shutdown")
        click.echo("Signer stopped.")
    except Exception as e:
        # Try PID file fallback
        if os.path.exists(config.pid_path):
            with open(config.pid_path) as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, signal.SIGTERM)
                os.unlink(config.pid_path)
                click.echo(f"Sent SIGTERM to PID {pid}")
            except OSError as e2:
                click.echo(f"Could not stop: {e2}")
        else:
            click.echo(f"Could not connect: {e}")


@main.command()
@click.option("--home", default=None, help="Override home directory")
def status(home):
    """Show service status."""
    from .client import SignerClient
    config = _get_config(home)
    try:
        client = SignerClient(socket_path=config.socket_path)
        result = client.status()
        click.echo(f"State: {result['state']}")
        click.echo(f"Uptime: {result.get('uptime', 0)}s")
        if "ttl_remaining" in result:
            click.echo(f"TTL remaining: {result['ttl_remaining']}s")
    except Exception as e:
        click.echo(f"Service not running ({e})")


@main.command()
@click.option("--timeout", default=0, help="Auto-lock timeout in seconds (0=permanent)")
@click.option("--home", default=None, help="Override home directory")
def unlock(timeout, home):
    """Unlock the signing service."""
    from .client import SignerClient
    config = _get_config(home)
    password = click.prompt("Enter password", hide_input=True)
    try:
        client = SignerClient(socket_path=config.socket_path)
        client.unlock(password=password, timeout=timeout)
        click.echo("Signer unlocked.")
    except Exception as e:
        raise click.ClickException(str(e))


@main.command()
@click.option("--home", default=None, help="Override home directory")
def lock(home):
    """Lock the signing service."""
    from .client import SignerClient
    config = _get_config(home)
    try:
        client = SignerClient(socket_path=config.socket_path)
        client.lock()
        click.echo("Signer locked.")
    except Exception as e:
        raise click.ClickException(str(e))


@main.command("change-password")
@click.option("--home", default=None, help="Override home directory")
def change_password(home):
    """Change the keystore encryption password."""
    config = _get_config(home)
    ks = Keystore.load(config.keystore_path)

    old_pass_str = click.prompt("Enter current password", hide_input=True)
    old_pass = bytearray(old_pass_str.encode("utf-8"))
    del old_pass_str

    # Decrypt with old password
    try:
        keys = ks.decrypt_all(old_pass)
    except Exception as e:
        zeroize(old_pass)
        raise click.ClickException(f"Wrong password: {e}")
    finally:
        zeroize(old_pass)

    new_pass_str = click.prompt("Enter new password", hide_input=True)
    confirm_str = click.prompt("Confirm new password", hide_input=True)
    if new_pass_str != confirm_str:
        for key in keys:
            if key.private_key:
                zeroize(key.private_key)
        raise click.ClickException("Passwords do not match")
    if len(new_pass_str) < config.min_password_length:
        for key in keys:
            if key.private_key:
                zeroize(key.private_key)
        raise click.ClickException(
            f"Password must be at least {config.min_password_length} characters"
        )

    new_pass = bytearray(new_pass_str.encode("utf-8"))
    del new_pass_str, confirm_str

    # Re-encrypt all keys with new password
    new_ks = Keystore(config.keystore_path)
    try:
        for key in keys:
            new_ks.add_key(
                name=key.name,
                key_type=key.key_type,
                address=key.address,
                private_key=key.private_key,
                password=bytearray(new_pass),  # copy each time
            )
        new_ks.save()
    finally:
        zeroize(new_pass)
        for key in keys:
            if key.private_key:
                zeroize(key.private_key)

    click.echo("Password changed successfully.")
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_cli.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/crypto_signer/cli.py tests/test_cli.py
git commit -m "feat: add CLI commands (init, add, list, remove, start, stop, lock, unlock)"
```

---

## Chunk 6: Web3 Middleware & Integration Tests

### Task 15: Web3 Middleware

**Files:**
- Create: `src/crypto_signer/web3/middleware.py`
- Create: `tests/test_web3_middleware.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/test_web3_middleware.py
import pytest

from crypto_signer.web3.middleware import SignerMiddleware


def test_middleware_instantiates():
    """Basic smoke test — middleware can be created with a mock client."""

    class MockEVM:
        def sign_transaction(self, tx):
            return {"signed_tx": "0xabc123", "tx_hash": "0xdef456"}

        def get_address(self):
            return "0x1234567890abcdef1234567890abcdef12345678"

    class MockClient:
        evm = MockEVM()

    mw = SignerMiddleware(client=MockClient())
    assert mw is not None
    assert mw._client.evm.get_address() == "0x1234567890abcdef1234567890abcdef12345678"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_web3_middleware.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write the implementation**

```python
# src/crypto_signer/web3/middleware.py
"""web3.py middleware for automatic transaction signing via crypto-signer."""

from ..client import SignerClient


class SignerMiddleware:
    """web3.py middleware that signs transactions using the crypto-signer daemon.

    Usage:
        from web3 import Web3
        from crypto_signer.web3 import SignerMiddleware

        w3 = Web3(Web3.HTTPProvider("https://..."))
        w3.middleware_onion.add(SignerMiddleware())
    """

    def __init__(self, client: SignerClient | None = None, socket_path: str | None = None):
        if client:
            self._client = client
        else:
            self._client = SignerClient(socket_path=socket_path)

    def __call__(self, make_request, w3):
        def middleware(method, params):
            if method == "eth_sendTransaction":
                tx = params[0]
                # Fill in 'from' if not present
                if "from" not in tx:
                    tx["from"] = self._client.evm.get_address()

                result = self._client.evm.sign_transaction(tx)
                # Send the signed raw transaction instead
                return make_request("eth_sendRawTransaction", [result["signed_tx"]])

            return make_request(method, params)

        return middleware
```

- [ ] **Step 4: Run tests**

Run: `python -m pytest tests/test_web3_middleware.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/crypto_signer/web3/middleware.py tests/test_web3_middleware.py
git commit -m "feat: add web3.py signing middleware"
```

---

### Task 16: Integration Test

**Files:**
- Create: `tests/test_integration.py`

- [ ] **Step 1: Write integration test**

This test exercises the full flow: create keystore -> start server -> unlock -> sign -> lock -> stop.

```python
# tests/test_integration.py
import json
import os
import socket
import threading
import time

import pytest

from crypto_signer.client import SignerClient
from crypto_signer.config import Config
from crypto_signer.keystore import Keystore
from crypto_signer.server import SignerServer
from crypto_signer.errors import SignerLockedError


TEST_EVM_KEY = bytes.fromhex(
    "4c0883a69102937d6231471b5dbb6204fe512961708279f15b0d7e4b2cd53f37"
)
TEST_EVM_ADDRESS = "0x2c7536E3605D9C16a7a3D7b1898e529396a65c23"
TEST_PASSWORD = "integration_test_pw"


@pytest.fixture
def full_env(tmp_path):
    """Full integration environment: keystore + server + client."""
    home = tmp_path / ".crypto-signer"
    home.mkdir()
    sock_path = str(home / "signer.sock")

    # Create keystore
    ks = Keystore(str(home / "keystore.json"))
    ks.add_key(
        name="test-evm",
        key_type="secp256k1",
        address=TEST_EVM_ADDRESS,
        private_key=bytearray(TEST_EVM_KEY),
        password=bytearray(TEST_PASSWORD.encode()),
    )
    ks.save()

    # Create config
    config = Config(
        home_dir=str(home),
        socket_path=sock_path,
        rate_limit=1000,
    )

    # Start server
    server = SignerServer(config)
    server.load_keystore()

    t = threading.Thread(target=server.serve, daemon=True)
    t.start()
    for _ in range(50):
        if os.path.exists(sock_path):
            break
        time.sleep(0.05)

    client = SignerClient(socket_path=sock_path)

    yield server, client

    server.shutdown()


def test_full_lifecycle(full_env):
    server, client = full_env

    # 1. Should be locked initially
    status = client.status()
    assert status["state"] == "locked"

    # 2. Signing should fail when locked
    with pytest.raises(SignerLockedError):
        client.evm.sign_transaction({})

    # 3. Unlock
    client.unlock(password=TEST_PASSWORD)
    status = client.status()
    assert status["state"] == "unlocked"

    # 4. Get address
    addr = client.evm.get_address()
    assert addr.lower() == TEST_EVM_ADDRESS.lower()

    # 5. Sign a transaction
    result = client.evm.sign_transaction({
        "to": "0x0000000000000000000000000000000000000000",
        "value": 0,
        "gas": 21000,
        "gasPrice": 1000000000,
        "nonce": 0,
        "chainId": 1,
    })
    assert "signed_tx" in result
    assert "tx_hash" in result

    # 6. Sign a message
    result = client.evm.sign_message("Hello Integration Test")
    assert "signature" in result

    # 7. Lock
    client.lock()
    status = client.status()
    assert status["state"] == "locked"

    # 8. Should fail again after locking
    with pytest.raises(SignerLockedError):
        client.evm.sign_transaction({})

    # 9. Re-unlock and verify
    client.unlock(password=TEST_PASSWORD)
    addr = client.evm.get_address()
    assert addr.lower() == TEST_EVM_ADDRESS.lower()


def test_wrong_password(full_env):
    server, client = full_env
    from crypto_signer.errors import InvalidPasswordError
    with pytest.raises(InvalidPasswordError):
        client.unlock(password="wrong_password_12")


def test_ping(full_env):
    server, client = full_env
    result = client.ping()
    assert result["status"] == "ok"
```

- [ ] **Step 2: Run integration tests**

Run: `python -m pytest tests/test_integration.py -v`
Expected: All 3 tests PASS

- [ ] **Step 3: Commit**

```bash
git add tests/test_integration.py
git commit -m "feat: add integration tests for full lifecycle"
```

---

### Task 17: Final — README & SECURITY docs

**Files:**
- Create: `README.md`
- Create: `SECURITY.md`

- [ ] **Step 1: Write README.md**

```markdown
# crypto-signer

Encrypted wallet + memory-resident signing service for Python crypto automation.

## What it does

- Encrypts private keys at rest (AES-256-GCM + Argon2id)
- Decrypts only into memory after password entry at startup
- Serves signing requests over Unix domain socket
- Business scripts never hold private keys directly
- Supports EVM (Ethereum, Polygon, BSC, etc.) and Solana

## Quick Start

pip install crypto-signer

# Initialize
crypto-signer init

# Add a key
crypto-signer add --name my-evm --type evm --key

# Start the signing service
crypto-signer start

## Usage in Python

from crypto_signer import SignerClient

signer = SignerClient()
signed_tx = signer.evm.sign_transaction({
    "to": "0x...",
    "value": 0,
    "gas": 21000,
    "gasPrice": 5000000000,
    "nonce": 0,
    "chainId": 1,
})

## Supported Platforms

- Linux (primary target)
- macOS (best-effort)
- Windows 11 (with platform adaptations)

## Security

See SECURITY.md for threat model and security boundaries.
```

- [ ] **Step 2: Write SECURITY.md**

```markdown
# Security

## Threat Model

This package protects against:
- Plaintext private keys on disk (.env files, config files)
- Accidental repository commits of secrets
- Low-sophistication attackers reading disk contents

This package does NOT protect against:
- Root-level host compromise (memory can be dumped)
- Python runtime memory inspection (GC timing, str immutability)
- Hardware-level attacks

## Security Boundaries

- Private keys are encrypted at rest with AES-256-GCM
- Password derivation uses Argon2id (memory-hard, GPU-resistant)
- Decrypted keys exist only in the signer daemon's memory
- Business processes never hold private keys
- IPC uses Unix domain sockets with 0600 permissions

## Known Limitations

- Python `str` objects are immutable and cannot be reliably zeroized
- `bytearray` zeroization is best-effort (GC may create copies)
- `mlock` may fail without appropriate permissions

## Future Enhancements

- C/Rust extension for secure memory management (mlock + guaranteed zeroize)
- memfd_secret support (Linux 5.14+)
- libsodium secure memory wrappers

## Recommendations

- Use project-specific derived keys, not master mnemonics
- Keep only small amounts in hot wallets
- Rotate keys periodically
- Run the signer as a dedicated user with minimal permissions
```

- [ ] **Step 3: Run full test suite**

Run: `python -m pytest tests/ -v`
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
git add README.md SECURITY.md
git commit -m "docs: add README and SECURITY documentation"
```
