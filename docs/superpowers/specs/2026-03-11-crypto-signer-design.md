# crypto-signer Design Spec

## 1. Overview

A reusable Python package that provides a local encrypted wallet + memory-resident signing service for crypto automation projects. Private keys are encrypted at rest and only decrypted into memory after manual password entry at startup. Business scripts never hold private keys directly — they request signatures via Unix domain socket IPC.

### Problem Statement

Running crypto automation scripts on VPS/cloud servers currently requires storing private keys or mnemonics in plaintext `.env` files. If the server is compromised, wallet assets are lost.

### Goals

1. Eliminate plaintext private keys from `.env` files and disk
2. Encrypt keys at rest, decrypt only into memory at runtime
3. Support service restart with manual password re-entry
4. Reusable across multiple Python crypto projects (installable via pip)
5. Decouple signing capability from business logic

### Non-Goals / Known Limitations

1. Cannot protect against root-level host compromise (memory can still be dumped)
2. Python runtime cannot provide absolute memory safety (v2: C/Rust extension)
3. Not a hardware wallet, TEE, or MPC solution
4. Only suitable for small-amount hot wallets, NOT large-value cold storage
5. Bitcoin chain support is deferred to a future version

### Supported Platforms

- **Linux** — Primary target (VPS/cloud servers)
- **macOS** — Best-effort support
- **Windows 11** — Supported with platform-specific adaptations (see Section 16)

### Security Philosophy

The goal is **risk reduction**, not absolute security. Specifically:
- Prevent disk leakage
- Prevent `.env` leakage
- Prevent accidental repository commits of secrets
- Prevent low-sophistication attackers from finding plaintext keys
- Minimize key exposure surface and duration within Python's constraints

## 2. Supported Chains

| Type | Chains | Key Algorithm |
|------|--------|---------------|
| EVM | Ethereum, Polygon, BSC, Arbitrum, Optimism, Avalanche C-Chain, all EVM-compatible | secp256k1 |
| Solana | Solana | Ed25519 |

## 3. Architecture

```
Business scripts / cron scripts
       |
       |  sign_transaction() / sign_message()
       v
 crypto-signer-client (library)
       |  Unix socket JSON protocol
       v
 crypto-signer (daemon)
  +-- State machine: INIT -> LOCKED -> UNLOCKED -> ERROR -> STOPPED
  +-- EVM signing engine (secp256k1)
  +-- Solana signing engine (Ed25519)
  +-- Security module: mlock / zeroize / disable core dump
  +-- Reads ~/.crypto-signer/keystore.json (encrypted)
```

### Components

1. **crypto-signer daemon** — Core process, holds decrypted private keys in memory, serves signing requests via Unix socket
2. **crypto-signer CLI** — Initialize encrypted keystore, manage service (start/stop/lock/unlock/status)
3. **crypto-signer client library** — Python library that business scripts import to request signatures
4. **web3.py middleware** — Optional adapter for seamless web3.py integration

## 4. Encrypted Storage

Single file: `~/.crypto-signer/keystore.json`

All keys are encrypted with the **same password**. Each key has an independent salt and IV for cryptographic hygiene (unique derived encryption keys per entry), but users only need to enter one password to unlock all keys.

```json
{
  "version": 1,
  "kdf": "argon2id",
  "kdf_params": {
    "memory_cost": 65536,
    "time_cost": 3,
    "parallelism": 4
  },
  "keys": [
    {
      "name": "my-evm",
      "key_type": "secp256k1",
      "address": "0x...",
      "cipher": "aes-256-gcm",
      "salt": "<base64>",
      "encrypted_key": "<base64>",
      "iv": "<base64>",
      "tag": "<base64>"
    }
  ]
}
```

KDF parameters (`kdf`, `kdf_params`) are global. Per-key fields are `salt`, `iv`, `tag`, and `encrypted_key`.

### Key Selection

v1 supports **one key per chain type**. If a keystore has one EVM key and one Solana key, chain type alone is sufficient to select the key. The `name` field is for human identification (display in `crypto-signer list`) and future multi-key-per-chain support. An optional `key_name` parameter is reserved in the IPC protocol for forward compatibility but is not required in v1.

### Encryption Flow

- **Init**: User enters private key (via `getpass`, no echo) + sets password -> Argon2id derives encryption key -> AES-256-GCM encrypts private key -> Write to keystore.json -> Immediately zeroize password, derived key, and plaintext private key from memory
- **Startup**: User enters password -> Derive key -> Decrypt all keys -> Verify each address matches (derive address from private key and compare) -> Zeroize password and derived key, retain only private keys in memory

### Algorithm Choices

- **Argon2id** — Strongest current password KDF, resistant to GPU/ASIC brute force
- **AES-256-GCM** — Authenticated encryption, detects ciphertext tampering
- **Address field** — Enables correctness verification after decryption

### Key Import Methods

- **Direct private key import**: Interactive prompt, no echo
- **Mnemonic derivation**: Enter mnemonic, auto-derive using chain-appropriate path (EVM: `m/44'/60'/0'/0/0`, Solana: `m/44'/501'/0'/0'`), store derived private key only, mnemonic is zeroized immediately and never persisted

### Input Security

- Private keys and mnemonics are NEVER passed as CLI arguments (would appear in `ps aux`, shell history, `/proc/pid/cmdline`)
- All sensitive input via `getpass` module (no echo)
- Sensitive data held in `bytearray` (mutable, can be explicitly zeroized), never `str`

## 5. State Machine

```
INIT --(load keystore)--> LOCKED --(enter password)--> UNLOCKED
                            ^                             |
                            |    lock / TTL expires        |
                            +-----------------------------+
LOCKED --(exit)--> STOPPED
UNLOCKED --(exit)--> STOPPED (zeroize memory)
ERROR --(retry unlock)--> LOCKED
ERROR --(exit)--> STOPPED (zeroize memory)
Any state --(fatal exception)--> ERROR
```

### States

| State | Description |
|-------|-------------|
| INIT | Service starting, loading keystore file |
| LOCKED | Keystore loaded, waiting for password. No keys in memory. |
| UNLOCKED | Keys decrypted and in memory. Ready to sign. |
| ERROR | Recoverable error (e.g., failed decryption). Can retry or exit. |
| STOPPED | Service shutting down. All keys zeroized. Terminal state. |

### Unlock Behavior

The `unlock` IPC call blocks until Argon2id derivation and decryption complete. Concurrent unlock requests while an unlock is in progress are rejected with a `SignerStateError`.

### Unlock Modes

- `unlock` — Permanent unlock until manual lock or exit
- `unlock --timeout 3600` — TTL unlock, auto-locks and zeroizes after timeout
- `lock` — Manual lock, immediately zeroizes private keys from memory

## 6. Security Hardening (v1)

| Measure | Description |
|---------|-------------|
| Disable core dump | Linux: `prctl(PR_SET_DUMPABLE, 0)`. Windows: skip with warning. |
| mlock | Linux/macOS: `mlock()`. Windows: `VirtualLock()` via `ctypes`. |
| Swap/pagefile check | Linux: warn if swap enabled. Windows: warn (pagefile cannot be easily disabled). |
| bytearray storage | Private keys and passwords stored in bytearray, byte-by-byte zeroize when done |
| Secrets not in logs | Logs, exceptions, `__repr__` never contain sensitive material |
| Socket/file permissions | Linux/macOS: socket `0600`. Windows: ACL restricted to current user. |
| Password policy | Minimum 8 characters, no empty passwords |
| Unlock backoff | Exponential backoff after consecutive failures (see below) |
| Request limits | Max message size 1MB, rate limit 60 signatures/minute (global across all keys) |

### Unlock Backoff Policy

- Initial delay: 1 second after first failure
- Doubles each consecutive failure: 1s, 2s, 4s, 8s, 16s
- After `max_unlock_attempts` (default 5) consecutive failures: signer remains LOCKED, rejects further unlock attempts until service restart
- Backoff counter resets to 0 after a successful unlock

### v2 Enhancement: Secure Memory Backend

Future versions will introduce C/Rust extensions for:
- `mlock` + `madvise` managed memory regions
- Guaranteed zeroization on deallocation
- `memfd_secret` support (Linux 5.14+)
- libsodium secure memory wrappers

## 7. IPC Protocol

Unix domain socket at `~/.crypto-signer/signer.sock`.

### Connection Model

**One request per connection**: client connects, sends one JSON request line, reads one JSON response line, then closes the connection. This avoids multiplexing complexity and simplifies error handling.

### Data Encoding Convention

All binary data (signatures, Solana transaction bytes, raw messages) is encoded as **base64 strings** in JSON. Hex-encoded strings (e.g., EVM addresses `0x...`) remain as-is.

### Request Format

```json
{"version": 1, "id": "req-001", "method": "sign_transaction", "params": {"chain": "evm", "tx": {"to": "0x...", "value": 100, ...}}}
```

- `version` — Protocol version, must be `1`
- `id` — Client-generated request ID, echoed in response for correlation
- `method` — Method name
- `params` — Method-specific parameters. `chain` is required for signing methods (`"evm"` or `"solana"`). Optional `key_name` reserved for future multi-key-per-chain support.

### Response Format

```json
{"id": "req-001", "result": {"signed_tx": "0x...", "tx_hash": "0x..."}}
```

### Error Format

```json
{"id": "req-001", "error": {"code": 1001, "message": "signer is locked"}}
```

### Methods

| Method | Description |
|--------|-------------|
| `sign_transaction` | Sign a transaction (EVM: dict with all fields; Solana: base64-encoded serialized tx) |
| `sign_message` | Sign a message (EVM: EIP-191 / Solana: base64-encoded raw bytes) |
| `sign_typed_data` | Sign EIP-712 typed data (EVM only; returns `UnsupportedChainError` if chain is not EVM) |
| `get_address` | Get wallet address for a given chain type |
| `status` | Query state (LOCKED/UNLOCKED, remaining TTL, uptime) |
| `lock` | Lock the signer (zeroize keys) |
| `unlock` | Unlock the signer (requires password in params) |
| `ping` | Health check |
| `shutdown` | Graceful shutdown |

### Signing Philosophy

The signer is a **"dumb signer"** — it signs whatever transaction data it receives. The client is responsible for populating all transaction fields (nonce, gas, chainId, etc.). The signer does NOT query any blockchain node or fill in missing fields. For EVM, required fields are: `to`, `value`, `gas`/`gasLimit`, `gasPrice` or `maxFeePerGas`+`maxPriorityFeePerGas`, `nonce`, `chainId`. For Solana, the client sends a fully serialized transaction as base64.

### Password Over IPC

The `unlock` method requires the password to be sent as a JSON string field over the Unix socket. This is acceptable because:
- The socket is local-only (no network exposure)
- File permissions restrict access to the current user (0600 on Unix, ACL on Windows)
- On Linux/macOS, peer UID is additionally verified via `SO_PEERCRED`/`getpeereid()`

The password is transmitted as a string in the client library API for ergonomics. Inside the daemon, it is immediately converted to `bytearray` and the string reference is discarded. The exposure window is minimal and bounded to the same-user local process boundary.

### IPC Security

- Socket file permissions: Linux/macOS `0600`, Windows ACL restricted to current user
- Peer authentication: Linux `SO_PEERCRED`, macOS `getpeereid()`, Windows relies on socket file ACL (no equivalent of `SO_PEERCRED`)
- No TCP — local only
- Max message length enforced (1MB)
- Reject malformed requests with `IPCProtocolError` without leaking internal state
- `shutdown` and `lock` are available to any authorized IPC client (same UID). This is by design — all processes running as the same user are considered equally trusted.

## 8. Client Library API

```python
from crypto_signer import SignerClient

signer = SignerClient()  # default ~/.crypto-signer/signer.sock
signer = SignerClient(socket_path="/custom/path/signer.sock")

# Service management
signer.ping()
signer.status()
signer.lock()
signer.unlock(password="...", timeout=3600)

# EVM
signer.evm.get_address()
signer.evm.sign_transaction(tx)
signer.evm.sign_message("Hello")
signer.evm.sign_typed_data(domain, types, value)

# Solana
signer.solana.get_address()
signer.solana.sign_transaction(tx_bytes)
signer.solana.sign_message(message_bytes)
```

The client library translates chain-specific sub-object calls (e.g., `signer.evm.sign_transaction(tx)`) into flat IPC requests with `"chain": "evm"` parameter.

### web3.py Integration

```python
from web3 import Web3
from crypto_signer.web3 import SignerMiddleware

w3 = Web3(Web3.HTTPProvider("https://..."))
w3.middleware_onion.add(SignerMiddleware())

# Transactions are automatically signed via the signing service
w3.eth.send_transaction({"to": "0x...", "value": 100})
```

## 9. Error Model

```
SignerError (base)
+-- ConnectionError          # Service not running / unreachable
+-- SignerLockedError        # Service is locked, must unlock first
+-- SignerStateError         # Operation invalid for current state (e.g., concurrent unlock)
+-- InvalidPasswordError     # Wrong password
+-- SigningError             # Signing failed (bad params, etc.)
+-- UnsupportedChainError    # Unsupported chain type or chain-method mismatch
+-- PolicyViolationError     # Rate limit or policy violation
+-- WalletFormatError        # Keystore format error / tampered / corrupted ciphertext
+-- IPCProtocolError         # Malformed request / invalid JSON / unknown method
+-- PermissionDeniedError    # UID mismatch / unauthorized client
```

### Error Code Table

| Code | Error Type | Description |
|------|------------|-------------|
| 1001 | SignerLockedError | Signer is locked |
| 1002 | SignerStateError | Invalid operation for current state |
| 1003 | InvalidPasswordError | Wrong password |
| 1004 | SigningError | Signing failed |
| 1005 | UnsupportedChainError | Unsupported chain or method |
| 1006 | PolicyViolationError | Rate limit exceeded |
| 1007 | WalletFormatError | Keystore error |
| 1008 | IPCProtocolError | Malformed request |
| 1009 | PermissionDeniedError | Unauthorized client |

Error messages MUST NEVER contain plaintext passwords, private keys, or mnemonics.

Non-fatal warnings (e.g., `mlock` unavailable, swap enabled) are logged but do not raise exceptions to IPC clients.

## 10. CLI

```bash
# Key management
crypto-signer init                                              # Initialize ~/.crypto-signer/ directory
crypto-signer add --name <name> --type <evm|solana> --key       # Import private key (interactive)
crypto-signer add --name <name> --type <evm|solana> --mnemonic  # Import from mnemonic (interactive)
crypto-signer list                                              # List stored keys (name, type, address)
crypto-signer remove --name <name>                              # Remove a key

# Service management
crypto-signer start                                             # Foreground start (for systemd/supervisor)
crypto-signer start -d                                          # Background daemon mode (see below)
crypto-signer stop                                              # Stop service
crypto-signer status                                            # Show status

# Lock/unlock
crypto-signer lock                                              # Lock signer (zeroize keys)
crypto-signer unlock [--timeout <seconds>]                      # Unlock (interactive password)

# Password management
crypto-signer change-password                                   # Change encryption password
```

### Daemon Mode (-d)

`crypto-signer start -d` prompts for the password interactively, decrypts and verifies all keys, then moves to background. On Linux/macOS this uses `fork()`. On Windows, it spawns a detached subprocess via `subprocess.Popen` with `CREATE_NO_WINDOW`/`DETACHED_PROCESS` flags. The signer enters UNLOCKED state before backgrounding. To re-lock, use `crypto-signer lock`. To re-unlock after locking, use `crypto-signer unlock` (which sends the password over the local socket).

### Foreground Mode

`crypto-signer start` (without `-d`) runs in the foreground and also prompts for the password at startup. This mode is intended for use with process managers like systemd or supervisor.

## 11. Configuration

File: `~/.crypto-signer/config.toml`

```toml
[signer]
socket_path = "~/.crypto-signer/signer.sock"
unlock_timeout = 0          # 0 = permanent unlock until lock/exit
disable_core_dump = true
try_mlock = true

[security]
max_request_size = 1048576  # 1MB
rate_limit = 60             # max signatures per minute (global)
min_password_length = 8
max_unlock_attempts = 5
```

## 12. Package Structure

```
crypto-signer/
+-- pyproject.toml
+-- README.md
+-- SECURITY.md
+-- src/
|   +-- crypto_signer/
|       +-- __init__.py
|       +-- cli.py                  # CLI entry point (click)
|       +-- config.py               # Config loading (TOML)
|       +-- errors.py               # Error definitions
|       +-- keystore.py             # Encrypted storage read/write
|       +-- server.py               # Unix socket signing service
|       +-- client.py               # SignerClient
|       +-- state.py                # State machine
|       +-- crypto/
|       |   +-- evm.py              # EVM signing engine
|       |   +-- solana.py           # Solana signing engine
|       +-- security/
|       |   +-- zeroize.py          # bytearray zeroization
|       |   +-- platform.py         # Platform detection + dispatch
|       |   +-- platform_unix.py    # Linux/macOS: mlock, prctl, SO_PEERCRED, chmod
|       |   +-- platform_win.py     # Windows: VirtualLock, ACL, no SO_PEERCRED
|       |   +-- harden.py           # High-level hardening (calls platform module)
|       |   +-- safe_input.py       # Secure input (getpass)
|       +-- web3/
|           +-- middleware.py       # web3.py integration
+-- tests/
    +-- test_keystore.py
    +-- test_server.py
    +-- test_crypto_evm.py
    +-- test_crypto_solana.py
    +-- test_state.py
    +-- test_security.py
    +-- test_integration.py
```

## 13. Dependencies

| Dependency | Purpose |
|------------|---------|
| `click` | CLI framework |
| `argon2-cffi` | Argon2id password KDF |
| `cryptography` | AES-256-GCM encryption |
| `eth-account` | EVM signing |
| `solders` | Solana signing |
| `tomli` / `tomllib` | TOML config parsing |
| `web3` | Optional, web3.py middleware integration |
| `pywin32` | Optional, native Windows ACL management (Windows only) |

## 14. v2 Roadmap

- C/Rust extension for secure memory management (mlock + madvise + guaranteed zeroize)
- Multi-key-per-chain support (using `key_name` parameter in IPC)
- Bitcoin chain support
- Multi-sig support
- Transaction whitelist/blacklist (restrict signable target contract addresses)
- Signing amount threshold alerts
- Audit logging system
- systemd deployment template
- Fine-grained signing policy engine

## 15. Cross-Platform Abstraction

All platform-specific functionality is isolated in `security/platform.py`, which dispatches to `platform_unix.py` or `platform_win.py` based on `sys.platform`.

```python
# security/platform.py
import sys

if sys.platform == "win32":
    from .platform_win import lock_memory, set_file_owner_only, harden_process, get_peer_credentials
else:
    from .platform_unix import lock_memory, set_file_owner_only, harden_process, get_peer_credentials
```

### Platform Feature Matrix

| Feature | Linux | macOS | Windows 11 |
|---------|-------|-------|------------|
| Unix domain socket (`AF_UNIX`) | Native | Native | Supported since Win10 1803 |
| Memory locking | `mlock()` | `mlock()` | `VirtualLock()` via `ctypes` |
| Disable core dump | `prctl(PR_SET_DUMPABLE, 0)` | `setrlimit(RLIMIT_CORE, 0)` | Not available (warning logged) |
| Swap/pagefile check | Check `/proc/swaps` | Check `sysctl vm.swapusage` | Warning only (pagefile always present) |
| Socket file permissions | `chmod 0600` | `chmod 0600` | ACL via `icacls` or `win32security` |
| Peer UID verification | `SO_PEERCRED` | `getpeereid()` | Not available (relies on socket file ACL) |
| Daemon mode (`-d`) | `os.fork()` | `os.fork()` | `subprocess.Popen` with `DETACHED_PROCESS` |

### Graceful Degradation

When a platform feature is unavailable (e.g., `prctl` on Windows, `SO_PEERCRED` on Windows), the system:
1. Logs a warning at startup (e.g., "Core dump protection not available on Windows")
2. Falls back to the next best available mechanism (e.g., ACL-only protection instead of ACL + UID verification)
3. Never blocks startup or refuses to operate — security features are best-effort enhancements

### Windows-Specific Notes

- **Socket path**: Windows `AF_UNIX` sockets have a max path length of 108 bytes. The default `~/.crypto-signer/signer.sock` is well within this limit. For users with deeply nested home directories, the `socket_path` config option allows customization.
- **ACL management**: On Windows, `set_file_owner_only()` uses `icacls` to restrict the keystore file and socket to the current user. If `pywin32` is installed, native Win32 security APIs are used instead for more reliable ACL management. `pywin32` is an optional dependency.
- **PID file**: On Windows, `-d` mode writes the child process PID to `~/.crypto-signer/signer.pid` for `crypto-signer stop` to use.

## 16. Product Decisions

These are non-negotiable project principles:

1. Plaintext private keys NEVER go into `.env` or environment variables
2. No remote TCP exposure of the signer service
3. No promise of protection against root-level host compromise
4. Designed for small-amount hot wallets, NOT main cold wallets
5. Business process and signing process are always separate
6. Recommend project-specific derived keys, not master mnemonics
7. Default mode: manual unlock then memory-resident until lock/exit
8. All documentation must clearly state security boundaries
9. Narrative is "risk reduction", not "absolute security"
