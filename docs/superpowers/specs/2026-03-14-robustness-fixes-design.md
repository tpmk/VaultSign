# Robustness Fixes — Design Spec

**Date**: 2026-03-14
**Scope**: Minimum viable fixes for real runtime issues, no architectural changes.

## 1. Windows ACL Fallback Validation

**File**: `src/crypto_signer/security/platform_win.py`

**Problem**: `icacls` fallback in `set_file_owner_only()` uses `check=False` and silently ignores failures. If both `win32api` and `icacls` fail, sensitive files retain default ACL.

**Fix**:
- Check `subprocess.run()` return code; log warning on non-zero.
- Log warning when `USERNAME` env var is missing (currently silently skips).

## 2. PID File Management

**File**: `src/crypto_signer/cli.py`

**Problem**:
- `start` does not check for an existing running process — overwrites PID file.
- Daemon crash leaves stale PID file; `stop` sends signal to wrong/dead process.
- `stop` via IPC shutdown does not clean up PID file.

**Fix**:
- Add `_check_stale_pid(config)` helper: read PID file, `os.kill(pid, 0)` to check liveness. If alive, abort with error. If dead, unlink stale file.
- Call `_check_stale_pid()` at start of `start` command.
- In `stop` command, unlink PID file after successful IPC shutdown.

## 3. Narrow Exception Handling

**Files**: `src/crypto_signer/crypto/evm.py`, `src/crypto_signer/security/platform_unix.py`, `src/crypto_signer/security/platform_win.py`

**Problem**: Broad `except Exception` catches mask programming errors and make debugging harder.

**Fix**:

| File | Function | Current | Narrowed To |
|------|----------|---------|-------------|
| `evm.py` | `sign_transaction` | `Exception` | `(ValueError, TypeError, KeyError)` |
| `evm.py` | `sign_message` | `Exception` | `(ValueError, TypeError, KeyError)` |
| `evm.py` | `sign_typed_data` | `Exception` | `(ValueError, TypeError, KeyError)` |
| `platform_unix.py` | `lock_memory` | `Exception` | `(OSError, ValueError, AttributeError)` |
| `platform_unix.py` | `harden_process` (core dump) | `Exception` | `(OSError, AttributeError)` |
| `platform_unix.py` | `harden_process` (swap) | `Exception` | `OSError` |
| `platform_unix.py` | `get_peer_credentials` | `Exception` | `(OSError, struct.error)` |
| `platform_win.py` | `lock_memory` | `Exception` | `(OSError, ValueError, AttributeError)` |

**Rationale**:
- `OSError` — system call failures (mlock, prctl, setrlimit, getsockopt)
- `ValueError` — ctypes `from_buffer` with bad argument
- `AttributeError` — missing ctypes symbol or module attribute on a given platform
- `struct.error` — peer credential data format mismatch
- `KeyError` / `TypeError` — eth-account dict field issues

## 4. Client Response Size Limit

**File**: `src/crypto_signer/client.py`

**Problem**: `_send()` recv loop has no size cap. A misbehaving server could cause OOM.

**Fix**: Add `_MAX_RESPONSE = 1048576` (1 MB, matching server `_MAX_MSG`). Break and raise `IPCProtocolError("Response too large")` when exceeded.

## 5. Daemon Signal Handling + PID Cleanup

**File**: `src/crypto_signer/cli.py`

**Problem**:
- Unix fork child has no signal handler — SIGTERM kills without cleanup.
- Windows thread mode does not clean PID file on exit.

**Fix**:
- **Unix** (`_start_daemon_unix`, child branch): Register SIGTERM/SIGINT handlers that call `server.shutdown()` + unlink PID file.
- **Windows** (`_start_daemon_windows`): Wrap `t.join()` in `try/finally` that unlinks PID file.

## Summary of Changes

| # | File | Est. Lines Changed |
|---|------|--------------------|
| 1 | `platform_win.py` | ~5 |
| 2 | `cli.py` | ~20 |
| 3 | `evm.py`, `platform_unix.py`, `platform_win.py` | ~15 |
| 4 | `client.py` | ~5 |
| 5 | `cli.py` | ~15 |
| **Total** | | **~60** |
