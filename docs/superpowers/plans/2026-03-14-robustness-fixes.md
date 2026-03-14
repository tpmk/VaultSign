# Robustness Fixes Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 5 real runtime robustness issues — Windows ACL validation, PID file management, narrowed exceptions, client response size limit, daemon signal handling.

**Architecture:** Targeted fixes in existing files only. No new modules, no architectural changes. Each task is independent and can be committed separately.

**Tech Stack:** Python 3.10+, click, ctypes, socket, signal, subprocess

**Spec:** `docs/superpowers/specs/2026-03-14-robustness-fixes-design.md`

---

## Chunk 1: All Tasks

### Task 1: Windows ACL Fallback Validation

**Files:**
- Modify: `src/crypto_signer/security/platform_win.py:45-54`
- Test: `tests/test_platform.py`

- [ ] **Step 1: Write failing tests for icacls warning and missing USERNAME**

In `tests/test_platform.py`, add these imports at the top of the file:

```python
import os
import logging
import subprocess

import pytest
from unittest.mock import patch
```

Then add these tests at the end of the file:

```python
def test_set_file_owner_only_icacls_warns_on_failure(tmp_path, caplog):
    """When win32api is unavailable and icacls fails, a warning is logged."""
    if sys.platform != "win32":
        pytest.skip("Windows-only test")

    from crypto_signer.security.platform_win import set_file_owner_only

    f = tmp_path / "test.txt"
    f.write_text("data")

    # patch.dict sets sys.modules entries to None, causing ImportError on
    # `import win32api` inside the function body — no reload needed.
    with patch.dict("sys.modules", {"win32api": None, "win32security": None, "ntsecuritycon": None}), \
         patch("crypto_signer.security.platform_win.subprocess.run") as mock_run, \
         caplog.at_level(logging.WARNING):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stderr=b"access denied",
        )
        set_file_owner_only(str(f))

    assert "icacls failed" in caplog.text


def test_set_file_owner_only_warns_missing_username(tmp_path, caplog):
    """When USERNAME env var is missing, a warning is logged."""
    if sys.platform != "win32":
        pytest.skip("Windows-only test")

    from crypto_signer.security.platform_win import set_file_owner_only

    f = tmp_path / "test.txt"
    f.write_text("data")

    with patch.dict("sys.modules", {"win32api": None, "win32security": None, "ntsecuritycon": None}), \
         patch.dict(os.environ, {"USERDOMAIN": "", "USERNAME": ""}, clear=False), \
         caplog.at_level(logging.WARNING):
        set_file_owner_only(str(f))

    assert "USERNAME" in caplog.text
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_platform.py::test_set_file_owner_only_icacls_warns_on_failure tests/test_platform.py::test_set_file_owner_only_warns_missing_username -v`
Expected: FAIL (no warnings logged currently, or skipped on non-Windows)

- [ ] **Step 3: Implement the fix**

In `src/crypto_signer/security/platform_win.py`, replace the `except ImportError` block in `set_file_owner_only`:

```python
    except ImportError:
        domain = os.environ.get("USERDOMAIN", "")
        username = os.environ.get("USERNAME", "")
        if not username:
            logger.warning(
                "Cannot set file permissions: USERNAME env var not set"
            )
            return
        qualified = f"{domain}\\{username}" if domain else username
        result = subprocess.run(
            ["icacls", path, "/inheritance:r", "/grant:r", f"{qualified}:(F)"],
            capture_output=True,
        )
        if result.returncode != 0:
            logger.warning(
                "icacls failed (rc=%d): %s",
                result.returncode,
                result.stderr.decode(errors="replace").strip(),
            )
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_platform.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/crypto_signer/security/platform_win.py tests/test_platform.py
git commit -m "fix: validate icacls fallback and warn on failure"
```

---

### Task 2: Narrow Exception Handling

**Files:**
- Modify: `src/crypto_signer/crypto/evm.py:30,40,54`
- Modify: `src/crypto_signer/security/platform_unix.py:28,49,58,77`
- Modify: `src/crypto_signer/security/platform_win.py:22`
- Test: `tests/test_crypto_evm.py`, `tests/test_platform.py`

- [ ] **Step 1: Write test that verifies unexpected exceptions propagate from evm.py**

In `tests/test_crypto_evm.py`, add:

```python
from unittest.mock import patch
from crypto_signer.errors import SigningError


def test_sign_transaction_propagates_unexpected_error(signer):
    """RuntimeError (not in narrowed set) should propagate, not be wrapped."""
    with patch.object(signer._account, "sign_transaction", side_effect=RuntimeError("unexpected")):
        with pytest.raises(RuntimeError):
            signer.sign_transaction({"to": "0x0", "value": 0, "gas": 21000, "gasPrice": 1000000000, "nonce": 0, "chainId": 1})


def test_sign_message_wraps_value_error(signer):
    """ValueError should be wrapped in SigningError."""
    with patch.object(signer._account, "sign_message", side_effect=ValueError("bad format")):
        with pytest.raises(SigningError, match="bad format"):
            signer.sign_message("test")
```

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/test_crypto_evm.py::test_sign_transaction_propagates_unexpected_error -v`
Expected: FAIL (currently catches all exceptions, wraps RuntimeError in SigningError)

- [ ] **Step 3: Narrow evm.py exceptions**

In `src/crypto_signer/crypto/evm.py`, change all three methods:

Line 30: `except Exception as e:` → `except (ValueError, TypeError, KeyError, AttributeError) as e:`
Line 40 (after edit, ~41): same change
Line 54 (after edit, ~55): same change

- [ ] **Step 4: Run evm tests**

Run: `uv run pytest tests/test_crypto_evm.py -v`
Expected: All PASS

- [ ] **Step 5: Narrow platform_unix.py exceptions**

In `src/crypto_signer/security/platform_unix.py`:

Line 28: `except Exception as e:` → `except (OSError, ValueError, AttributeError) as e:`
Line 49: `except Exception as e:` → `except (OSError, AttributeError) as e:`
Line 58: `except Exception as e:` → `except OSError as e:`
Line 77: `except Exception:` → `except (OSError, struct.error):`

- [ ] **Step 6: Narrow platform_win.py lock_memory exception**

In `src/crypto_signer/security/platform_win.py`:

Line 22: `except Exception as e:` → `except (OSError, ValueError, AttributeError) as e:`

- [ ] **Step 7: Run all platform tests**

Run: `uv run pytest tests/test_platform.py tests/test_crypto_evm.py -v`
Expected: All PASS

- [ ] **Step 8: Commit**

```bash
git add src/crypto_signer/crypto/evm.py src/crypto_signer/security/platform_unix.py src/crypto_signer/security/platform_win.py tests/test_crypto_evm.py
git commit -m "fix: narrow exception handling for better debugging"
```

---

### Task 3: Client Response Size Limit

**Files:**
- Modify: `src/crypto_signer/client.py:125-132`
- Test: `tests/test_client.py`

- [ ] **Step 1: Write failing test for oversized response**

In `tests/test_client.py`, add at the top of the file with the other imports:

```python
from crypto_signer.client import _MAX_RESPONSE
```

Then add test:

```python
def test_oversized_response_raises_protocol_error(tmp_path):
    """Response exceeding _MAX_RESPONSE should raise IPCProtocolError."""
    # Send a response larger than the limit (without a newline so client keeps reading)
    oversized = b"x" * (_MAX_RESPONSE + 1)
    kwargs = _one_shot_server(tmp_path, oversized)
    client = SignerClient(**kwargs)
    with pytest.raises(IPCProtocolError, match="too large"):
        client.ping()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_client.py::test_oversized_response_raises_protocol_error -v`
Expected: FAIL (_MAX_RESPONSE not defined, no size check)

- [ ] **Step 3: Implement size limit**

In `src/crypto_signer/client.py`, add after line 10 (`_HAS_AF_UNIX = ...`):

```python
_MAX_RESPONSE = 1048576  # 1 MB, matches server _MAX_MSG
```

Then replace the recv loop in `_send()` (lines 125-132):

```python
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
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_client.py -v`
Expected: All PASS

- [ ] **Step 5: Commit**

```bash
git add src/crypto_signer/client.py tests/test_client.py
git commit -m "fix: add response size limit to client recv loop"
```

---

### Task 4: PID File Management

**Files:**
- Modify: `src/crypto_signer/cli.py:197-298`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write test for stale PID detection**

In `tests/test_cli.py`, add these imports at the top of the file:

```python
import os
import signal
import click
from unittest.mock import patch
```

Then add these tests at the end of the file:

```python
from crypto_signer.cli import _check_stale_pid


def test_check_stale_pid_cleans_dead_process(tmp_path):
    """Stale PID file (dead process) should be cleaned up."""
    home = str(tmp_path / ".crypto-signer")
    os.makedirs(home, exist_ok=True)
    pid_file = os.path.join(home, "signer.pid")

    # Write a PID that doesn't exist
    with open(pid_file, "w") as f:
        f.write("99999999")

    from crypto_signer.config import Config
    config = Config(home_dir=home)

    with patch("crypto_signer.cli.os.kill", side_effect=OSError("No such process")):
        _check_stale_pid(config)

    assert not os.path.exists(pid_file)


def test_check_stale_pid_aborts_if_alive(tmp_path):
    """If PID is alive, should raise ClickException."""
    home = str(tmp_path / ".crypto-signer")
    os.makedirs(home, exist_ok=True)
    pid_file = os.path.join(home, "signer.pid")

    with open(pid_file, "w") as f:
        f.write("12345")

    from crypto_signer.config import Config
    config = Config(home_dir=home)

    with patch("crypto_signer.cli.os.kill", return_value=None):  # process exists
        with pytest.raises(click.ClickException, match="already running"):
            _check_stale_pid(config)


def test_check_stale_pid_treats_permission_error_as_alive(tmp_path):
    """PermissionError means process exists but inaccessible — treat as alive."""
    home = str(tmp_path / ".crypto-signer")
    os.makedirs(home, exist_ok=True)
    pid_file = os.path.join(home, "signer.pid")

    with open(pid_file, "w") as f:
        f.write("12345")

    from crypto_signer.config import Config
    config = Config(home_dir=home)

    with patch("crypto_signer.cli.os.kill", side_effect=PermissionError("Access denied")):
        with pytest.raises(click.ClickException, match="already running"):
            _check_stale_pid(config)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cli.py::test_check_stale_pid_cleans_dead_process -v`
Expected: FAIL (_check_stale_pid not defined)

- [ ] **Step 3: Implement _check_stale_pid**

In `src/crypto_signer/cli.py`, add after the `_TYPE_MAP` definition (line 42):

```python
def _check_stale_pid(config: Config) -> None:
    """Check for stale PID file and clean up or abort."""
    if not os.path.exists(config.pid_path):
        return
    try:
        with open(config.pid_path) as f:
            pid = int(f.read().strip())
    except (ValueError, OSError):
        os.unlink(config.pid_path)
        return
    try:
        os.kill(pid, 0)
    except PermissionError:
        # Process exists but inaccessible — treat as alive
        raise click.ClickException(f"Signer already running (PID {pid})")
    except OSError:
        # Process does not exist — clean up stale PID file
        os.unlink(config.pid_path)
        return
    # os.kill succeeded — process is alive
    raise click.ClickException(f"Signer already running (PID {pid})")
```

- [ ] **Step 4: Call _check_stale_pid in start command**

In `src/crypto_signer/cli.py`, in the `start()` function, add after `config = _get_config(home)` (line 202) and **before** the password prompt so users don't enter a password only to be told the daemon is already running:

```python
    _check_stale_pid(config)
```

- [ ] **Step 5: Clean up PID file in stop command**

In `src/crypto_signer/cli.py`, in the `stop()` function, after `client._send("shutdown")` (line 285), add:

```python
        if os.path.exists(config.pid_path):
            os.unlink(config.pid_path)
```

- [ ] **Step 6: Run tests**

Run: `uv run pytest tests/test_cli.py -v`
Expected: All PASS

- [ ] **Step 7: Commit**

```bash
git add src/crypto_signer/cli.py tests/test_cli.py
git commit -m "fix: PID file management — stale detection and cleanup"
```

---

### Task 5: Daemon Signal Handling + PID Cleanup

**Files:**
- Modify: `src/crypto_signer/cli.py:240-274`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write test for Unix daemon PID cleanup on shutdown**

In `tests/test_cli.py`, add (note: `import os`, `import signal`, and `import sys` should already be at the top from Task 4):

```python
def test_start_daemon_unix_cleanup(tmp_path):
    """Unix daemon child should clean PID file on signal."""
    import sys
    if sys.platform == "win32":
        pytest.skip("Unix-only test")

    home = str(tmp_path / ".crypto-signer")
    os.makedirs(home, exist_ok=True)
    pid_file = os.path.join(home, "signer.pid")

    from crypto_signer.config import Config
    config = Config(home_dir=home)

    # Write a PID file as the parent would
    with open(pid_file, "w") as f:
        f.write(str(os.getpid()))

    # Verify our signal handler cleans up
    from crypto_signer.cli import _daemon_cleanup_handler
    handler = _daemon_cleanup_handler(config, None)
    handler(signal.SIGTERM, None)

    assert not os.path.exists(pid_file)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_cli.py::test_start_daemon_unix_cleanup -v`
Expected: FAIL (_daemon_cleanup_handler not defined)

- [ ] **Step 3: Implement daemon signal handling**

In `src/crypto_signer/cli.py`, add a helper before `_start_daemon_unix`:

```python
def _daemon_cleanup_handler(config, server):
    """Return a signal handler that cleans up PID file and shuts down server."""
    def handler(sig, frame):
        if server is not None:
            server.shutdown()
        if os.path.exists(config.pid_path):
            os.unlink(config.pid_path)
    return handler
```

Update `_start_daemon_unix` child branch (after `os.setsid()`):

```python
def _start_daemon_unix(server, config):
    """Fork to background on Unix."""
    pid = os.fork()
    if pid > 0:
        with open(config.pid_path, "w") as f:
            f.write(str(pid))
        server.lock()
        click.echo(f"Daemon started (PID {pid})")
        return
    os.setsid()
    handler = _daemon_cleanup_handler(config, server)
    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)
    from .security.harden import apply_hardening
    apply_hardening()
    server.serve()
```

Update `_start_daemon_windows` to wrap `t.join()`:

```python
def _start_daemon_windows(server, config):
    """Start daemon on Windows."""
    from .security.harden import apply_hardening
    apply_hardening()

    with open(config.pid_path, "w") as f:
        f.write(str(os.getpid()))

    click.echo(f"Daemon started (PID {os.getpid()})")

    t = threading.Thread(target=server.serve, daemon=False)
    t.start()

    try:
        import ctypes
        ctypes.windll.kernel32.FreeConsole()
    except Exception:
        pass

    try:
        t.join()
    finally:
        if os.path.exists(config.pid_path):
            os.unlink(config.pid_path)
```

- [ ] **Step 4: Run all tests**

Run: `uv run pytest tests/test_cli.py -v`
Expected: All PASS

- [ ] **Step 5: Run full test suite**

Run: `uv run pytest tests/ -v`
Expected: All 65+ tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/crypto_signer/cli.py tests/test_cli.py
git commit -m "fix: daemon signal handling and PID cleanup on exit"
```
