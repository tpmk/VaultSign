# Runtime Hardening Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix 5 runtime correctness and platform reliability defects in crypto-signer without changing user-facing command semantics.

**Architecture:** Each fix stays within its existing module boundary. Config path derivation is purely data-layer. VirtualLock is isolated to platform_win.py. IPC validation adds a pre-dispatch layer in server.py. Client discovery extends the existing `_resolve_tcp_from_socket_path()` path. Windows daemon lifecycle replaces the blocking thread-join with a detached subprocess spawned via a hidden `_serve` click subcommand.

**Tech Stack:** Python 3.10+, click, subprocess, socket, ctypes, pytest, unittest.mock

**Spec:** `docs/superpowers/specs/2026-03-18-runtime-hardening-fixes-design.md`

---

## Chunk 1: Config and Platform Fixes (isolated, low-risk)

### Task 1: Fix Config.from_file() path derivation

**Files:**
- Modify: `src/crypto_signer/config.py:53-69`
- Test: `tests/test_config.py`

- [ ] **Step 1: Write the failing tests**

In `tests/test_config.py`, add:

```python
def test_from_file_sets_home_dir_to_config_parent(tmp_path):
    """from_file() should derive home_dir from the config file's directory."""
    config_dir = tmp_path / "custom-home"
    config_dir.mkdir()
    toml_file = config_dir / "config.toml"
    toml_file.write_text(
        '[signer]\n'
        'unlock_timeout = 300\n'
    )
    c = Config.from_file(str(toml_file))
    assert c.home_dir == str(config_dir)
    assert c.keystore_path == str(config_dir / "keystore.json")
    assert c.socket_path == str(config_dir / "signer.sock")
    assert c.pid_path == str(config_dir / "signer.pid")


def test_from_file_explicit_socket_path_not_overridden(tmp_path):
    """If socket_path is set in the TOML, it should not be overridden."""
    config_dir = tmp_path / "custom-home"
    config_dir.mkdir()
    toml_file = config_dir / "config.toml"
    toml_file.write_text(
        '[signer]\n'
        'socket_path = "/custom/signer.sock"\n'
    )
    c = Config.from_file(str(toml_file))
    assert c.home_dir == str(config_dir)
    assert c.socket_path == "/custom/signer.sock"


def test_load_home_dir_overrides_from_file(tmp_path):
    """Config.load(home_dir=...) should override from_file's home_dir."""
    override_dir = tmp_path / "override-home"
    override_dir.mkdir()
    (override_dir / "config.toml").write_text('[signer]\n')

    c = Config.load(home_dir=str(override_dir))
    assert c.home_dir == str(override_dir)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_config.py::test_from_file_sets_home_dir_to_config_parent tests/test_config.py::test_from_file_explicit_socket_path_not_overridden -v`

Expected: FAIL — `c.home_dir` returns default `~/.crypto-signer` instead of `config_dir`.

- [ ] **Step 3: Implement the fix**

In `src/crypto_signer/config.py`, modify `from_file()` — inject `home_dir` into kwargs before calling `cls(**kwargs)`:

```python
@classmethod
def from_file(cls, path: str) -> "Config":
    kwargs = {}
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except (FileNotFoundError, OSError):
        return cls()
    # Set home_dir to config file's parent so __post_init__ derives
    # socket_path, keystore_path, etc. relative to it.
    kwargs["home_dir"] = str(Path(path).parent)
    signer = data.get("signer", {})
    security = data.get("security", {})
    for key in ("socket_path", "unlock_timeout", "disable_core_dump", "try_mlock"):
        if key in signer:
            kwargs[key] = signer[key]
    for key in ("max_request_size", "rate_limit", "min_password_length", "max_unlock_attempts"):
        if key in security:
            kwargs[key] = security[key]
    return cls(**kwargs)
```

- [ ] **Step 4: Run all config tests**

Run: `uv run pytest tests/test_config.py -v`

Expected: All PASS (new + existing `test_config_from_toml`, `test_config_missing_file_uses_defaults`).

- [ ] **Step 5: Commit**

```bash
git add src/crypto_signer/config.py tests/test_config.py
git commit -m "fix: Config.from_file() derives home_dir from config file directory"
```

---

### Task 2: Fix VirtualLock ctypes signatures

**Files:**
- Modify: `src/crypto_signer/security/platform_win.py:13-24`
- Test: `tests/test_platform.py`

- [ ] **Step 1: Write the failing test**

In `tests/test_platform.py`, add:

```python
def test_lock_memory_sets_virtuallock_argtypes():
    """VirtualLock must have explicit ctypes argtypes for 64-bit correctness."""
    if sys.platform != "win32":
        pytest.skip("Windows-only test")

    import ctypes
    from crypto_signer.security.platform_win import lock_memory

    buf = bytearray(64)
    lock_memory(buf)

    kernel32 = ctypes.windll.kernel32
    assert kernel32.VirtualLock.argtypes == [ctypes.c_void_p, ctypes.c_size_t]
    assert kernel32.VirtualLock.restype == ctypes.c_int
```

- [ ] **Step 2: Run test to verify it fails**

Run: `uv run pytest tests/test_platform.py::test_lock_memory_sets_virtuallock_argtypes -v`

Expected: FAIL (on Windows) or SKIP (on non-Windows).

- [ ] **Step 3: Implement the fix**

Replace `lock_memory` in `src/crypto_signer/security/platform_win.py`:

```python
def lock_memory(buf: bytearray) -> bool:
    try:
        kernel32 = ctypes.windll.kernel32
        kernel32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        kernel32.VirtualLock.restype = ctypes.c_int
        addr = (ctypes.c_char * len(buf)).from_buffer(buf)
        result = kernel32.VirtualLock(ctypes.addressof(addr), len(buf))
        if result == 0:
            logger.warning("VirtualLock failed: error=%d", ctypes.GetLastError())
            return False
        return True
    except (OSError, ValueError, AttributeError, ctypes.ArgumentError) as e:
        logger.warning("VirtualLock unavailable: %s", e)
        return False
```

- [ ] **Step 4: Run all platform tests**

Run: `uv run pytest tests/test_platform.py -v`

Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_signer/security/platform_win.py tests/test_platform.py
git commit -m "fix: set explicit VirtualLock ctypes argtypes for 64-bit correctness"
```

---

## Chunk 2: IPC Validation

### Task 3: Add params type guard and catch-all to _handle_request

**Files:**
- Modify: `src/crypto_signer/server.py:146-176`
- Test: `tests/test_server.py`

- [ ] **Step 1: Write failing tests for params type guard and catch-all**

In `tests/test_server.py`, add after `test_invalid_method`:

```python
def test_params_as_string_returns_protocol_error(running_server):
    """params must be a dict; a string should return IPCProtocolError."""
    server, address, token = running_server
    resp = _send_request(address, {
        "version": 1, "id": "v1", "method": "ping", "params": "not-a-dict"
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008
    assert "params must be an object" in resp["error"]["message"]


def test_params_as_list_returns_protocol_error(running_server):
    """params as a list should return IPCProtocolError."""
    server, address, token = running_server
    resp = _send_request(address, {
        "version": 1, "id": "v2", "method": "ping", "params": [1, 2, 3]
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008


def test_params_as_null_returns_protocol_error(running_server):
    """params as null should return IPCProtocolError."""
    server, address, token = running_server
    resp = _send_request(address, {
        "version": 1, "id": "v3", "method": "ping", "params": None
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008


def test_unexpected_exception_returns_internal_error(running_server):
    """Unexpected handler exceptions should return 'Internal error'."""
    server, address, token = running_server
    original = server._handle_ping
    def bad_handler(params):
        raise RuntimeError("something went wrong")
    server._handle_ping = bad_handler
    try:
        resp = _send_request(address, {
            "version": 1, "id": "ie1", "method": "ping", "params": {}
        }, token=token)
        assert "error" in resp
        assert resp["error"]["code"] == 1008
        assert "Internal error" in resp["error"]["message"]
    finally:
        server._handle_ping = original
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_server.py::test_params_as_string_returns_protocol_error tests/test_server.py::test_unexpected_exception_returns_internal_error -v`

Expected: FAIL — string params causes handler `AttributeError`, catch-all doesn't exist.

- [ ] **Step 3: Implement params type guard and catch-all**

In `src/crypto_signer/server.py`, replace lines 169-176 (the method/params/dispatch section of `_handle_request`):

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_server.py::test_params_as_string_returns_protocol_error tests/test_server.py::test_params_as_list_returns_protocol_error tests/test_server.py::test_params_as_null_returns_protocol_error tests/test_server.py::test_unexpected_exception_returns_internal_error -v`

Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_signer/server.py tests/test_server.py
git commit -m "fix: add params type guard and catch-all to IPC request handling"
```

---

### Task 4: Add per-method param validation

**Files:**
- Modify: `src/crypto_signer/server.py:178-194` (add `_validate_params`, modify `_dispatch`)
- Test: `tests/test_server.py`

- [ ] **Step 1: Write failing tests for per-method validation**

In `tests/test_server.py`, add:

```python
def test_unlock_password_must_be_string(running_server):
    server, address, token = running_server
    resp = _send_request(address, {
        "version": 1, "id": "uv1", "method": "unlock",
        "params": {"password": 12345, "timeout": 0}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008


def test_unlock_timeout_must_be_nonneg_integer(running_server):
    server, address, token = running_server
    resp = _send_request(address, {
        "version": 1, "id": "uv2", "method": "unlock",
        "params": {"password": "testpass1234", "timeout": "five"}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008


def test_unlock_timeout_negative_rejected(running_server):
    server, address, token = running_server
    resp = _send_request(address, {
        "version": 1, "id": "uv3", "method": "unlock",
        "params": {"password": "testpass1234", "timeout": -1}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008


def test_sign_transaction_tx_must_be_object(running_server):
    server, address, token = running_server
    _send_request(address, {
        "version": 1, "id": "st0", "method": "unlock",
        "params": {"password": "testpass1234"}
    }, token=token)
    resp = _send_request(address, {
        "version": 1, "id": "st1", "method": "sign_transaction",
        "params": {"chain": "evm", "tx": "not-an-object"}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008


def test_sign_message_message_must_be_string(running_server):
    server, address, token = running_server
    _send_request(address, {
        "version": 1, "id": "sm0", "method": "unlock",
        "params": {"password": "testpass1234"}
    }, token=token)
    resp = _send_request(address, {
        "version": 1, "id": "sm1", "method": "sign_message",
        "params": {"chain": "evm", "message": 12345}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008


def test_get_key_name_must_be_string(running_server):
    server, address, token = running_server
    _send_request(address, {
        "version": 1, "id": "gkv0", "method": "unlock",
        "params": {"password": "testpass1234"}
    }, token=token)
    resp = _send_request(address, {
        "version": 1, "id": "gkv1", "method": "get_key",
        "params": {"name": 123}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_server.py::test_unlock_password_must_be_string tests/test_server.py::test_unlock_timeout_must_be_nonneg_integer tests/test_server.py::test_unlock_timeout_negative_rejected -v`

Expected: FAIL — these will hit the catch-all ("Internal error") rather than specific validation errors, since no per-method validation exists. Some may accidentally pass via catch-all (code 1008), but the message won't match specific validation text.

- [ ] **Step 3: Add `_validate_params` helper and call from `_dispatch`**

In `src/crypto_signer/server.py`, add before `_handle_ping` (around line 196):

```python
    def _validate_params(self, method: str, params: dict) -> None:
        """Validate params shape for known methods. Raises IPCProtocolError."""
        if method == "unlock":
            password = params.get("password")
            if password is not None and not isinstance(password, str):
                raise IPCProtocolError("unlock.password must be a string")
            timeout = params.get("timeout")
            if timeout is not None:
                if not isinstance(timeout, int) or isinstance(timeout, bool):
                    raise IPCProtocolError("unlock.timeout must be an integer")
                if timeout < 0:
                    raise IPCProtocolError("unlock.timeout must be >= 0")
        elif method == "get_key":
            name = params.get("name")
            if name is not None and not isinstance(name, str):
                raise IPCProtocolError("get_key.name must be a string")
        elif method == "sign_transaction":
            tx = params.get("tx")
            if tx is not None and not isinstance(tx, dict):
                raise IPCProtocolError("sign_transaction.tx must be an object")
        elif method == "sign_message":
            message = params.get("message")
            if message is not None and not isinstance(message, str):
                raise IPCProtocolError("sign_message.message must be a string")
        elif method == "sign_typed_data":
            for field_name in ("domain", "types", "value"):
                val = params.get(field_name)
                if val is not None and not isinstance(val, dict):
                    raise IPCProtocolError(
                        f"sign_typed_data.{field_name} must be an object"
                    )
        elif method == "get_address":
            chain = params.get("chain")
            if chain is not None and not isinstance(chain, str):
                raise IPCProtocolError("get_address.chain must be a string")
```

In `_dispatch`, add validation call before handler invocation:

```python
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
        self._validate_params(method, params)
        return handler(params)
```

- [ ] **Step 4: Run all server tests**

Run: `uv run pytest tests/test_server.py -v`

Expected: All PASS (new + existing).

- [ ] **Step 5: Commit**

```bash
git add src/crypto_signer/server.py tests/test_server.py
git commit -m "fix: add per-method IPC param validation"
```

---

## Chunk 3: Client Discovery

### Task 5: Fix default SignerClient() discovery on Windows

**Files:**
- Modify: `src/crypto_signer/client.py:62-71`
- Modify: `src/crypto_signer/server.py:287-291` (docstring only)
- Test: `tests/test_client.py`

- [ ] **Step 1: Write failing tests**

In `tests/test_client.py`, add:

```python
def test_default_client_reads_discovery_files_on_windows(tmp_path):
    """SignerClient() with no args on Windows should read signer.port/signer.token."""
    home_dir = tmp_path / ".crypto-signer"
    home_dir.mkdir()
    (home_dir / "signer.port").write_text("54321")
    (home_dir / "signer.token").write_text("test-token-abc")

    with patch("crypto_signer.client._HAS_AF_UNIX", False), \
         patch("crypto_signer.client._default_socket_path",
               return_value=str(home_dir / "signer.sock")):
        client = SignerClient()

    assert client._host == "127.0.0.1"
    assert client._port == 54321
    assert client._token == "test-token-abc"
    assert client._socket_path is None


def test_default_client_raises_when_no_discovery_files(tmp_path):
    """SignerClient() on Windows should fail-fast if discovery files don't exist."""
    home_dir = tmp_path / ".crypto-signer"
    home_dir.mkdir()

    with patch("crypto_signer.client._HAS_AF_UNIX", False), \
         patch("crypto_signer.client._default_socket_path",
               return_value=str(home_dir / "signer.sock")):
        with pytest.raises(SignerConnectionError, match="port file"):
            SignerClient()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_client.py::test_default_client_reads_discovery_files_on_windows tests/test_client.py::test_default_client_raises_when_no_discovery_files -v`

Expected: FAIL — first test: client hardcodes port 9473 instead of reading files.

- [ ] **Step 3: Implement the fix**

In `src/crypto_signer/client.py`, replace lines 65-71:

```python
        elif not socket_path and not host:
            # Default discovery: Unix socket or Windows TCP discovery files
            if _HAS_AF_UNIX:
                self._socket_path = _default_socket_path()
            else:
                # Windows: read port/token from default home's discovery files
                self._resolve_tcp_from_socket_path(_default_socket_path())
```

- [ ] **Step 4: Add docstring to `_serve_unix`**

In `src/crypto_signer/server.py`, update the docstring at line 288:

```python
    def _serve_unix(self) -> None:
        """Serve on a Unix domain socket.

        Assumes no concurrent server is using the socket path. Callers
        should verify externally (e.g. via PID check) before calling.
        """
```

- [ ] **Step 5: Run all client and server tests**

Run: `uv run pytest tests/test_client.py tests/test_server.py -v`

Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add src/crypto_signer/client.py src/crypto_signer/server.py tests/test_client.py
git commit -m "fix: SignerClient() default discovery reads Windows TCP discovery files"
```

---

## Chunk 4: Windows Daemon Lifecycle

### Task 6: Replace blocking Windows daemon with detached subprocess

**Files:**
- Create: `src/crypto_signer/__main__.py`
- Modify: `src/crypto_signer/cli.py:244-275` (start command), `cli.py:319-343` (_start_daemon_windows)
- Test: `tests/test_cli.py`

- [ ] **Step 1: Create `__main__.py`**

Create `src/crypto_signer/__main__.py` (required for `python -m crypto_signer _serve`):

```python
"""Allow running as python -m crypto_signer."""
from .cli import main

main()
```

- [ ] **Step 2: Write failing tests for the new daemon model**

In `tests/test_cli.py`, add imports at the top:

```python
import subprocess
import sys
```

Then add tests:

```python
def test_start_daemon_windows_spawns_subprocess(tmp_path):
    """Windows daemon should spawn a subprocess, not block on thread.join()."""
    home = str(tmp_path / ".crypto-signer")
    os.makedirs(home, exist_ok=True)
    ks_path = os.path.join(home, "keystore.json")
    with open(ks_path, "w") as f:
        json.dump({"version": 1, "kdf": "argon2id", "kdf_params": {}, "keys": []}, f)

    from crypto_signer.cli import _start_daemon_windows
    from crypto_signer.config import Config

    config = Config(home_dir=home)

    with patch("crypto_signer.cli.subprocess.Popen") as mock_popen:
        mock_proc = mock_popen.return_value
        mock_proc.stdout.readline.return_value = json.dumps(
            {"status": "ready", "pid": 12345}
        ).encode() + b"\n"
        mock_proc.poll.return_value = None

        _start_daemon_windows("test-password", config)

    mock_popen.assert_called_once()
    call_args = mock_popen.call_args
    cmd = call_args[0][0] if call_args[0] else call_args.kwargs.get("args", [])
    assert "_serve" in " ".join(str(c) for c in cmd)


def test_start_daemon_windows_reports_child_error(tmp_path):
    """If child reports error, parent should raise ClickException."""
    home = str(tmp_path / ".crypto-signer")
    os.makedirs(home, exist_ok=True)
    ks_path = os.path.join(home, "keystore.json")
    with open(ks_path, "w") as f:
        json.dump({"version": 1, "kdf": "argon2id", "kdf_params": {}, "keys": []}, f)

    from crypto_signer.cli import _start_daemon_windows
    from crypto_signer.config import Config

    config = Config(home_dir=home)

    with patch("crypto_signer.cli.subprocess.Popen") as mock_popen:
        mock_proc = mock_popen.return_value
        mock_proc.stdout.readline.return_value = json.dumps(
            {"status": "error", "message": "bad password"}
        ).encode() + b"\n"
        mock_proc.poll.return_value = None

        with pytest.raises(click.ClickException, match="bad password"):
            _start_daemon_windows("test-password", config)


def test_start_daemon_windows_handles_timeout(tmp_path):
    """If child doesn't respond within timeout, parent should report error."""
    home = str(tmp_path / ".crypto-signer")
    os.makedirs(home, exist_ok=True)
    ks_path = os.path.join(home, "keystore.json")
    with open(ks_path, "w") as f:
        json.dump({"version": 1, "kdf": "argon2id", "kdf_params": {}, "keys": []}, f)

    from crypto_signer.cli import _start_daemon_windows
    from crypto_signer.config import Config

    config = Config(home_dir=home)

    with patch("crypto_signer.cli.subprocess.Popen") as mock_popen, \
         patch("crypto_signer.cli._DAEMON_READY_TIMEOUT", 0.1):
        mock_proc = mock_popen.return_value
        # Simulate a hanging child: readline blocks, so the Thread.join
        # times out and is_alive() returns True.
        import time
        def slow_readline():
            time.sleep(5)
            return b""
        mock_proc.stdout.readline.side_effect = slow_readline

        with pytest.raises(click.ClickException, match="did not respond"):
            _start_daemon_windows("test-password", config)

        mock_proc.kill.assert_called_once()
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_cli.py::test_start_daemon_windows_spawns_subprocess -v`

Expected: FAIL — `_start_daemon_windows` has wrong signature (currently takes `(server, config)` not `(password_str, config)`).

- [ ] **Step 4: Implement the new `_start_daemon_windows` and `_serve` subcommand**

In `src/crypto_signer/cli.py`:

**4a.** Add `import subprocess` to imports (top of file, around line 8). Keep `import threading` — it's still needed for the timeout reader thread in `_start_daemon_windows`.

**4b.** Add a constant after the imports:

```python
_DAEMON_READY_TIMEOUT = 30
```

**4c.** Replace the `start` command (lines 244-288) — restructure so Windows daemon path gets the password string before unlock:

```python
@main.command()
@click.option("-d", "daemon", is_flag=True, help="Run in background")
@click.option("--home", default=None, help="Override home directory")
def start(daemon, home):
    """Start the signing service."""
    from .server import SignerServer
    from .security.harden import apply_hardening

    config = _get_config(home)
    _check_stale_pid(config)
    server = SignerServer(config)
    server.load_keystore()

    # Prompt for password
    password_str = click.prompt("Enter password to unlock", hide_input=True)

    if daemon and sys.platform == "win32":
        # Windows daemon: child process will unlock, not us
        _start_daemon_windows(password_str, config)
        del password_str
        return

    password = bytearray(password_str.encode("utf-8"))
    del password_str

    try:
        server.unlock(password, config.unlock_timeout)
    except Exception as e:
        raise click.ClickException(str(e))

    click.echo("Signer unlocked and ready.")

    if daemon:
        _start_daemon_unix(server, config)
        return

    # Foreground mode
    apply_hardening()

    def _signal_handler(sig, frame):
        click.echo("\nShutting down...")
        server.shutdown()

    signal.signal(signal.SIGINT, _signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _signal_handler)

    server.serve()
```

**4d.** Replace `_start_daemon_windows` (lines 319-343):

```python
def _start_daemon_windows(password_str: str, config: Config):
    """Spawn a detached child process to run the signer daemon on Windows."""
    cmd = [sys.executable, "-m", "crypto_signer", "_serve", "--home", config.home_dir]

    # CREATE_NO_WINDOW=0x08000000 | DETACHED_PROCESS=0x00000008
    creation_flags = (0x08000000 | 0x00000008) if sys.platform == "win32" else 0

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        creationflags=creation_flags,
    )

    # Send password via stdin pipe, then close it
    proc.stdin.write(password_str.encode("utf-8"))
    proc.stdin.close()

    # Wait for ready signal from child (with timeout).
    # Use a thread to read stdout so we can apply a timeout on Windows
    # where selectors don't work on pipe file descriptors.
    line_container = [b""]

    def _read_line():
        try:
            line_container[0] = proc.stdout.readline()
        except Exception:
            pass

    reader = threading.Thread(target=_read_line, daemon=True)
    reader.start()
    reader.join(timeout=_DAEMON_READY_TIMEOUT)

    if reader.is_alive():
        proc.kill()
        raise click.ClickException(
            f"Daemon did not respond within {_DAEMON_READY_TIMEOUT}s"
        )

    line = line_container[0]

    if not line.strip():
        exit_code = proc.poll()
        stderr_out = ""
        try:
            stderr_out = proc.stderr.read().decode(errors="replace").strip()
        except Exception:
            pass
        msg = stderr_out or f"Daemon process did not start (exit code: {exit_code})"
        raise click.ClickException(msg)

    try:
        signal_data = json.loads(line.decode("utf-8").strip())
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise click.ClickException(f"Invalid ready signal from daemon: {e}")

    if signal_data.get("status") == "ready":
        pid = signal_data.get("pid", proc.pid)
        click.echo(f"Daemon started (PID {pid})")
    else:
        msg = signal_data.get("message", "Unknown error")
        raise click.ClickException(f"Daemon failed to start: {msg}")
```

**4e.** Add the hidden `_serve` subcommand after the `lock` command:

```python
@main.command("_serve", hidden=True)
@click.option("--home", required=True, help="Home directory")
def _serve_cmd(home):
    """Internal: long-running server process for Windows daemon mode."""
    config = _get_config(home)

    try:
        from .server import SignerServer
        from .security.harden import apply_hardening

        server = SignerServer(config)
        server.load_keystore()

        # Read password from stdin pipe (binary mode for correct encoding)
        password_bytes = sys.stdin.buffer.read()
        password = bytearray(password_bytes)
        del password_bytes

        try:
            server.unlock(password, config.unlock_timeout)
        except Exception as e:
            signal_data = {"status": "error", "message": str(e)}
            sys.stdout.write(json.dumps(signal_data) + "\n")
            sys.stdout.flush()
            return

        apply_hardening()

        # Write PID file
        with open(config.pid_path, "w") as f:
            f.write(str(os.getpid()))

        # Emit ready signal
        signal_data = {"status": "ready", "pid": os.getpid()}
        sys.stdout.write(json.dumps(signal_data) + "\n")
        sys.stdout.flush()

        # Redirect stdout/stderr to devnull to avoid BrokenPipeError
        devnull = open(os.devnull, "w")
        sys.stdout = devnull
        sys.stderr = devnull

        try:
            server.serve()
        finally:
            server.shutdown()
            if os.path.exists(config.pid_path):
                os.unlink(config.pid_path)
    except Exception as e:
        try:
            signal_data = {"status": "error", "message": str(e)}
            sys.stdout.write(json.dumps(signal_data) + "\n")
            sys.stdout.flush()
        except Exception:
            pass
```

- [ ] **Step 5: Run all CLI tests**

Run: `uv run pytest tests/test_cli.py -v`

Expected: All PASS (new + existing).

- [ ] **Step 6: Commit**

```bash
git add src/crypto_signer/__main__.py src/crypto_signer/cli.py tests/test_cli.py
git commit -m "fix: Windows daemon mode spawns detached subprocess instead of blocking"
```

---

## Chunk 5: Final Verification

### Task 7: Full regression suite

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `uv run pytest tests/ -v`

Expected: All PASS. No regressions.

- [ ] **Step 2: Verify imports**

Run: `python -c "from crypto_signer import SignerClient; print('OK')"`

Expected: `OK`

- [ ] **Step 3: Verify `_serve` is hidden**

Run: `uv run python -m crypto_signer --help`

Expected: `_serve` does NOT appear in help output.

- [ ] **Step 4: Review git diff for scope**

Run: `git diff --stat HEAD~6`

Expected: Only the intended files changed:
- `src/crypto_signer/__main__.py` (new)
- `src/crypto_signer/config.py`
- `src/crypto_signer/client.py`
- `src/crypto_signer/server.py`
- `src/crypto_signer/security/platform_win.py`
- `src/crypto_signer/cli.py`
- `tests/test_config.py`
- `tests/test_client.py`
- `tests/test_server.py`
- `tests/test_platform.py`
- `tests/test_cli.py`
