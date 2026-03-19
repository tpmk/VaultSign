# Runtime Hardening Fixes Design Spec

## 1. Overview

This spec fixes a set of correctness and platform reliability issues in `crypto-signer` without changing the primary user-facing command set.

The work targets five concrete defects:

1. Windows daemon mode does not actually detach and blocks the caller.
2. Windows default client discovery does not match the server's random-port TCP transport.
3. Malformed IPC requests can terminate a connection without returning a structured protocol error.
4. Windows `VirtualLock` integration is unreliable on 64-bit systems due to incorrect ctypes usage.
5. `Config.from_file()` resolves derived paths against the default home instead of the config file directory.

## 2. Goals

1. Make `crypto-signer start -d` behave as a true background start on Windows.
2. Make `SignerClient()` work with default settings on both Unix and Windows.
3. Guarantee structured IPC error responses for malformed requests instead of silent disconnects.
4. Restore functional best-effort memory locking on Windows.
5. Make `Config.from_file()` a reliable public API for config-relative path derivation.

## 3. Non-Goals

1. Replacing the Windows transport with named pipes or a Windows Service.
2. Introducing a full third-party schema validation library.
3. Reworking the keystore format, signer state model, or existing successful request semantics.

## 4. Design Summary

The implementation stays within the existing module boundaries:

- `client.py` owns transport discovery and connection setup.
- `cli.py` owns daemon lifecycle orchestration.
- `server.py` owns protocol validation and structured error behavior.
- `platform_win.py` owns Windows-specific hardening primitives.
- `config.py` owns path derivation rules.

This keeps the fixes focused on the existing responsibility boundaries instead of spreading platform-specific logic across the codebase.

## 5. Client Discovery

### Current Problem

On Windows, the server binds TCP to `127.0.0.1` with an ephemeral port and writes discovery artifacts to:

- `signer.port`
- `signer.token`

However, `SignerClient()` with no arguments currently defaults to `127.0.0.1:9473`, which does not match how the server actually runs.

### Proposed Behavior

`SignerClient()` will use a single default-home discovery flow:

1. Determine the default home directory.
2. Derive the default `signer.sock` path from that directory.
3. On Unix:
   - connect directly to that socket path
4. On Windows:
   - treat the socket path as a locator for the home directory
   - read `signer.port` and `signer.token` from the same directory
   - connect to `127.0.0.1:<discovered port>`

### Explicit Overrides

- `SignerClient(socket_path=...)` keeps working on all platforms.
- `SignerClient(host=..., port=...)` remains the explicit TCP override.
- `SignerClient()` becomes the correct cross-platform default.

### Unix Socket Unlink and Split-Brain Prevention

The audit noted that `_serve_unix()` unconditionally unlinks an existing socket file before binding, which could orphan a running daemon (the old process keeps running but clients can no longer reach it).

At the CLI layer, `_check_stale_pid()` already prevents starting a second daemon when the PID file indicates a live process. This means the unlink only executes when no daemon is believed to be running, which is the correct cleanup path for stale socket files left by a crashed process.

Adding a redundant PID check inside `_serve_unix()` would duplicate logic and couple the server to CLI-layer concerns. Instead, this spec takes the following position:

- **CLI path** (`crypto-signer start`): protected by `_check_stale_pid()` — no change needed.
- **Direct `SignerServer.serve()` calls** (programmatic usage): callers are responsible for lifecycle management. This is consistent with the existing design where `SignerServer` is a building block, not a standalone daemon manager.
- **Documentation**: add a docstring note to `_serve_unix()` stating that it assumes no concurrent server is using the socket, and that callers should verify this externally (e.g. via PID check).

## 6. Windows Daemon Lifecycle

### Current Problem

`start -d` on Windows starts `server.serve()` in a thread and immediately `join()`s that thread, so the CLI process never actually detaches.

### Proposed Behavior

Introduce an internal CLI entrypoint for the long-running server process via a **hidden click subcommand** `_serve` (`hidden=True`). The parent spawns it with `sys.executable -m crypto_signer _serve`. The user-visible command remains `crypto-signer start -d`, but the implementation changes:

1. The parent CLI process validates config, keystore availability, and **prompts for the password**.
2. The parent spawns a child Python process (with `CREATE_NO_WINDOW` on Windows) that runs an internal server command. The password is passed to the child via a **stdin pipe** and the pipe is closed immediately after the write.
3. The child process:
   - reads the password from stdin
   - unlocks the keystore
   - starts the signer server
   - writes PID / discovery files
   - writes a JSON ready message to **stdout** (see Ready Signaling below)
4. The parent reads the child's stdout, waits for the ready/failure signal, reports the result, and exits.

**Why parent prompts, child receives via pipe**: The child is spawned detached (`CREATE_NO_WINDOW` / `DETACHED_PROCESS`), so it has no console and cannot prompt interactively. Passing the password over a stdin pipe keeps the UX unchanged (user types the password before the process detaches) and avoids writing secrets to disk or environment variables.

### Ready Signaling

The parent communicates with the child via its **stdout pipe**. The child writes exactly one JSON line to stdout:

- Success: `{"status": "ready", "pid": <int>}`
- Failure: `{"status": "error", "message": "<reason>"}`

The parent reads this single line (with a timeout, e.g. 30s), then:

- On `"ready"`: prints success message and exits 0.
- On `"error"` or timeout or child exit: prints the error and exits 1.

This avoids false-positive starts and does not require polling files.

### Scope Control

This is intentionally a process-model fix, not a service-manager redesign.

## 7. IPC Validation and Error Semantics

### Current Problem

The server only serializes `SignerError` subclasses. Unexpected type errors from malformed params can bypass the protocol error model and result in an empty response.

### Proposed Behavior

Add a lightweight request validation layer before dispatching to handlers.

Each method will validate its expected `params` shape and primitive types. Examples:

- `status`: `params` must be an object
- `unlock.password`: required string
- `unlock.timeout`: integer, `>= 0`
- `get_key.name`: required non-empty string
- `sign_transaction.tx`: object
- `sign_message.message`: string
- `sign_typed_data.domain/types/value`: objects

Validation failures return `IPCProtocolError` with a structured JSON response.

### Unknown Fields Policy

Unknown fields in `params` are **silently ignored**. Validation only checks known fields for type and presence. This preserves forward compatibility — a newer client sending extra fields won't break against an older server.

### Catch-All in `_handle_request`

Even with per-method validation, unexpected exceptions (e.g. a future code path raising `TypeError` or `KeyError`) must not escape the protocol boundary. The `_handle_request` method's `_dispatch` call site currently only catches `SignerError`. Add a second `except Exception` clause that:

1. Logs the full traceback at `ERROR` level (for operator diagnostics).
2. Returns a structured `IPCProtocolError("Internal error")` response to the client.

This guarantees every request produces a JSON response, regardless of what goes wrong inside a handler.

### Error Contract

Malformed requests should always produce one of:

- `Invalid JSON`
- `Unsupported protocol version`
- method-specific `IPCProtocolError`
- `Internal error` (catch-all for unexpected failures)

They should not produce:

- dropped connections
- raw Python exceptions in the client
- empty responses for protocol mistakes

## 8. Windows Memory Locking

### Current Problem

`VirtualLock` is called without explicit ctypes signatures. On 64-bit Windows this can mis-handle pointer-sized arguments and fail before the OS call is made.

### Proposed Behavior

In `platform_win.py`:

1. Resolve `kernel32.VirtualLock`
2. Set explicit `argtypes` and `restype`
3. Pass a pointer-sized address value and size using the correct ctypes types
4. Keep the existing "best effort" contract:
   - success returns `True`
   - failure logs a warning and returns `False`

This preserves the current security model while making it function correctly on real Windows systems.

## 9. Config Path Derivation

### Current Problem

`Config.from_file(path)` currently reads values from the specified TOML file but leaves `home_dir` anchored to the default user directory. That makes `keystore_path`, `socket_path`, and related derived paths inconsistent with the config source.

### Proposed Behavior

`Config.from_file(path)` will:

1. parse the file
2. set `home_dir` to `Path(path).parent`
3. derive default runtime paths relative to that directory unless explicitly overridden in the file

`Config.load(home_dir=...)` remains the override-oriented helper, but its behavior becomes consistent with `from_file()`.

## 10. Testing Strategy

All fixes will be implemented with test-first coverage.

### Tests to Add or Update

- `tests/test_client.py`
  - default client discovery on Windows-style TCP discovery files
- `tests/test_cli.py`
  - Windows daemon path launches an independent subprocess flow instead of blocking thread join semantics
- `tests/test_server.py`
  - malformed `unlock` params return structured `IPCProtocolError`
  - malformed request param container types are rejected cleanly
  - unexpected handler exception (e.g. simulated `TypeError`) returns `Internal error` instead of empty response
- `tests/test_platform.py`
  - `VirtualLock` wrapper uses pointer-safe ctypes calling conventions
- `tests/test_config.py`
  - `Config.from_file()` derives home-relative paths from the config file directory

### Regression Requirement

The existing full pytest suite must continue to pass after the changes.

## 11. Risks and Mitigations

### Risk: Windows daemon start becomes more complex

Mitigation:

- isolate the complexity inside a private CLI entrypoint
- keep user-facing commands unchanged
- add startup handshake tests

### Risk: validation layer rejects requests that used to be accidentally accepted

Mitigation:

- only reject clearly malformed input
- keep valid request payloads unchanged
- return explicit protocol errors instead of ambiguous failures

### Risk: platform-specific tests are brittle

Mitigation:

- use targeted mocks around subprocess and ctypes boundaries
- keep integration assertions focused on observable behavior, not implementation details

## 12. Implementation Scope

### Files to Modify

- `src/crypto_signer/client.py`
- `src/crypto_signer/cli.py`
- `src/crypto_signer/server.py`
- `src/crypto_signer/security/platform_win.py`
- `src/crypto_signer/config.py`
- `tests/test_client.py`
- `tests/test_cli.py`
- `tests/test_server.py`
- `tests/test_platform.py`
- `tests/test_config.py`

### New Files

None required.
