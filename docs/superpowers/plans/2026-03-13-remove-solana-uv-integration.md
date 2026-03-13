# Remove Solana Support & Full uv Integration — Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove all Solana/ed25519 chain support (while keeping the multi-chain abstraction) and adopt uv as the primary environment manager.

**Architecture:** Two work streams executed sequentially. Work Stream 1 deletes Solana files, strips Solana references from 6 source files and 3 test files, and removes `solders` + `bip-utils` dependencies. Work Stream 2 cleans up `pyproject.toml` (duplicate tomli, duplicate dev deps), adds `.python-version`, updates README, and regenerates `uv.lock`. All `pyproject.toml` changes are consolidated before `uv lock`.

**Tech Stack:** Python 3.12, uv, pytest, Hatchling.

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `src/crypto_signer/crypto/solana.py` | Delete | Solana signing engine |
| `tests/test_crypto_solana.py` | Delete | Solana signing tests |
| `src/crypto_signer/server.py` | Modify L27, L46, L102-103, L122-124, L227-230, L238-245 | Remove SolanaSigner import, `_solana` attr, load/zeroize/dispatch, simplify `_handle_sign_transaction` |
| `src/crypto_signer/client.py` | Modify L18, L72 | Remove `_ChainClient` docstring Solana ref, remove `self.solana` |
| `src/crypto_signer/keystore.py` | Modify L112-120, L141 | Remove ed25519 branch in `_derive_address_from_key`, remove from `chain_types` |
| `src/crypto_signer/cli.py` | Modify L39-44, L48, L92, L147-181, L201 | Remove Solana from `_derive_address`, `_TYPE_MAP`, `click.Choice`, `_derive_from_mnemonic`, `list_keys` |
| `tests/test_client.py` | Modify L122-127 | Remove `test_solana_get_address` |
| `tests/test_integration.py` | No changes needed | Already EVM-only |
| `pyproject.toml` | Modify L17-20, L23-29, L41-45 | Remove solders/bip-utils deps, fix tomli dup, unify dev deps |
| `README.md` | Modify L11 | Remove Solana mention |
| `.python-version` | Create | Pin dev Python to 3.12 |

---

## Chunk 1: Remove Solana from Source Code

### Task 1: Remove Solana from server.py

**Files:**
- Modify: `src/crypto_signer/server.py:27, 46, 102-103, 122-124, 227-230`

- [ ] **Step 1: Remove SolanaSigner import and `_solana` attribute**

In `src/crypto_signer/server.py`, delete line 27:

```python
from .crypto.solana import SolanaSigner
```

Replace line 46:

```python
        self._solana: SolanaSigner | None = None
```

with nothing (delete it).

- [ ] **Step 2: Remove Solana key loading in `unlock`**

Replace lines 102-103:

```python
                elif key.key_type == "ed25519":
                    self._solana = SolanaSigner(key.private_key)
```

with nothing (delete both lines).

- [ ] **Step 3: Remove Solana zeroization in `lock`**

Replace lines 122-124:

```python
            if self._solana:
                self._solana.zeroize()
                self._solana = None
```

with nothing (delete all three lines).

- [ ] **Step 4: Remove Solana case in `_get_chain_signer`**

Replace lines 227-230:

```python
        elif chain == "solana":
            if self._solana is None:
                raise UnsupportedChainError("No Solana key loaded")
            return self._solana
```

with nothing (delete all four lines).

- [ ] **Step 5: Simplify `_handle_sign_transaction`**

The `else` branch (line 244-245) passes `tx` as a string (Solana base64 format). With Solana gone, simplify to always use the EVM dict format.

Replace lines 238-245:

```python
    def _handle_sign_transaction(self, params: dict) -> dict:
        self._check_rate_limit()
        chain = params.get("chain", "")
        signer = self._get_chain_signer(chain)
        if chain == "evm":
            return signer.sign_transaction(params.get("tx", {}))
        else:
            return signer.sign_transaction(params.get("tx", ""))
```

with:

```python
    def _handle_sign_transaction(self, params: dict) -> dict:
        self._check_rate_limit()
        chain = params.get("chain", "")
        signer = self._get_chain_signer(chain)
        return signer.sign_transaction(params.get("tx", {}))
```

- [ ] **Step 6: Run existing server tests**

Run: `uv run pytest tests/test_server.py -v`
Expected: All PASS. No tests relied on Solana-specific server paths.

- [ ] **Step 7: Commit**

```bash
git add src/crypto_signer/server.py
git commit -m "refactor: remove Solana support from server"
```

---

### Task 2: Remove Solana from client.py

**Files:**
- Modify: `src/crypto_signer/client.py:18, 72`
- Modify: `tests/test_client.py:122-127`

- [ ] **Step 1: Update `_ChainClient` docstring and remove `self.solana`**

In `src/crypto_signer/client.py`, replace line 18:

```python
    """Chain-specific sub-client (evm or solana)."""
```

with:

```python
    """Chain-specific sub-client."""
```

Delete line 72:

```python
        self.solana = _ChainClient(self._send, "solana")
```

- [ ] **Step 2: Remove `test_solana_get_address` from tests**

In `tests/test_client.py`, delete lines 122-127:

```python
def test_solana_get_address(mock_server):
    address, set_response = mock_server
    set_response("get_address", {"address": "SoL123"})
    client = _make_client(address)
    addr = client.solana.get_address()
    assert addr == "SoL123"
```

- [ ] **Step 3: Run client tests**

Run: `uv run pytest tests/test_client.py -v`
Expected: All PASS (8 tests remaining after removing 1).

- [ ] **Step 4: Commit**

```bash
git add src/crypto_signer/client.py tests/test_client.py
git commit -m "refactor: remove Solana support from client"
```

---

### Task 3: Remove Solana from keystore.py

**Files:**
- Modify: `src/crypto_signer/keystore.py:112-120, 141`

- [ ] **Step 1: Remove ed25519 branch in `_derive_address_from_key`**

In `src/crypto_signer/keystore.py`, replace lines 112-120:

```python
    elif key_type == "ed25519":
        try:
            from .crypto.solana import SolanaSigner
            signer = SolanaSigner(bytearray(private_key))
            addr = signer.get_address()
            signer.zeroize()
            return addr
        except ImportError:
            return ""
```

with nothing (delete all lines).

- [ ] **Step 2: Remove ed25519 from `chain_types` in `add_key`**

Replace line 141:

```python
        chain_types = {"secp256k1": "evm", "ed25519": "solana"}
```

with:

```python
        chain_types = {"secp256k1": "evm"}
```

- [ ] **Step 3: Run keystore tests**

Run: `uv run pytest tests/test_keystore.py -v`
Expected: All PASS.

- [ ] **Step 4: Commit**

```bash
git add src/crypto_signer/keystore.py
git commit -m "refactor: remove Solana support from keystore"
```

---

### Task 4: Remove Solana from cli.py

**Files:**
- Modify: `src/crypto_signer/cli.py:39-44, 48, 92, 147-181, 201`

- [ ] **Step 1: Remove Solana branch from `_derive_address`**

In `src/crypto_signer/cli.py`, replace lines 39-44:

```python
    elif key_type in ("solana", "ed25519"):
        from .crypto.solana import SolanaSigner
        signer = SolanaSigner(bytearray(private_key))  # copy
        addr = signer.get_address()
        signer.zeroize()
        return addr
```

with nothing (delete all lines).

- [ ] **Step 2: Remove `"solana"` from `_TYPE_MAP`**

Replace line 48:

```python
_TYPE_MAP = {"evm": "secp256k1", "solana": "ed25519"}
```

with:

```python
_TYPE_MAP = {"evm": "secp256k1"}
```

- [ ] **Step 3: Remove `"solana"` from `click.Choice`**

Replace line 92:

```python
@click.option("--type", "key_type", required=True, type=click.Choice(["evm", "solana"]))
```

with:

```python
@click.option("--type", "key_type", required=True, type=click.Choice(["evm"]))
```

- [ ] **Step 4: Clean up `_derive_from_mnemonic`**

Replace the entire function (lines 147-181) with:

```python
def _derive_from_mnemonic(mnemonic: str, key_type: str) -> bytearray:
    """Derive a private key from a mnemonic phrase using BIP-44 paths.

    EVM: m/44'/60'/0'/0/0
    """
    try:
        if key_type == "evm":
            from eth_account import Account
            Account.enable_unaudited_hdwallet_features()
            acct = Account.from_mnemonic(mnemonic, account_path="m/44'/60'/0'/0/0")
            return bytearray(acct.key)
        else:
            raise click.ClickException(f"Unsupported key type for mnemonic: {key_type}")
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(f"Mnemonic derivation failed: {e}")
```

- [ ] **Step 5: Fix `list_keys` display logic**

Replace lines 200-202:

```python
    for k in keys:
        chain = "evm" if k["key_type"] == "secp256k1" else "solana"
        click.echo(f"  {k['name']}  [{chain}]  {k['address']}")
```

with:

```python
    reverse_type = {v: k for k, v in _TYPE_MAP.items()}
    for k in keys:
        chain = reverse_type.get(k["key_type"], k["key_type"])
        click.echo(f"  {k['name']}  [{chain}]  {k['address']}")
```

- [ ] **Step 6: Run CLI tests**

Run: `uv run pytest tests/test_cli.py -v`
Expected: All PASS.

- [ ] **Step 7: Commit**

```bash
git add src/crypto_signer/cli.py
git commit -m "refactor: remove Solana support from CLI"
```

---

### Task 5: Delete Solana files

**Files:**
- Delete: `src/crypto_signer/crypto/solana.py`
- Delete: `tests/test_crypto_solana.py`

- [ ] **Step 1: Delete files**

```bash
git rm src/crypto_signer/crypto/solana.py tests/test_crypto_solana.py
```

- [ ] **Step 2: Verify no Solana references remain in source code**

```bash
grep -ri "solana\|ed25519\|SolanaSigner\|solders\|bip.utils" src/ || echo "Clean: no Solana references in src/"
```

Expected: "Clean: no Solana references in src/"

- [ ] **Step 3: Run full test suite to verify nothing is broken**

Run: `uv run pytest tests/ -v`
Expected: All PASS.

- [ ] **Step 4: Commit**

```bash
git commit -m "refactor: delete Solana signing engine and tests"
```

---

## Chunk 2: pyproject.toml Cleanup & uv Integration

### Task 6: Clean up pyproject.toml and add .python-version

**Files:**
- Modify: `pyproject.toml:12-21, 23-29, 41-45`
- Create: `.python-version`

- [ ] **Step 1: Remove Solana dependencies from `pyproject.toml`**

In `pyproject.toml`, replace lines 12-21:

```toml
dependencies = [
    "click>=8.0",
    "argon2-cffi>=23.1",
    "cryptography>=41.0",
    "eth-account>=0.11",
    "solders>=0.21",
    "bip-utils>=2.9",
    "tomli>=2.0; python_version < '3.11'",
    "tomli>=2.0",
]
```

with:

```toml
dependencies = [
    "click>=8.0",
    "argon2-cffi>=23.1",
    "cryptography>=41.0",
    "eth-account>=0.11",
    "tomli>=2.0; python_version < '3.11'",
]
```

This removes `solders`, `bip-utils`, and the duplicate unconditional `tomli`.

- [ ] **Step 2: Remove duplicate dev dependencies from optional-dependencies**

Replace lines 23-29:

```toml
[project.optional-dependencies]
web3 = ["web3>=6.0"]
win = ["pywin32>=306"]
dev = [
    "pytest>=7.0",
    "pytest-asyncio>=0.21",
]
```

with:

```toml
[project.optional-dependencies]
web3 = ["web3>=6.0"]
win = ["pywin32>=306"]
```

The `[dependency-groups].dev` section (lines 41-45) stays as-is — it's the modern standard for dev deps and what `uv sync` uses.

- [ ] **Step 3: Create `.python-version`**

Create `.python-version` with content:

```
3.12
```

This pins the dev environment. `requires-python = ">=3.10"` in pyproject.toml stays — that's the package compatibility range.

- [ ] **Step 4: Regenerate `uv.lock`**

```bash
uv lock
```

Expected: Lock file regenerated without `solders`, `bip-utils`, or their transitive deps.

- [ ] **Step 5: Verify Solana deps are gone from uv.lock**

```bash
grep -i "solders\|bip.utils\|pycryptodome\|ed25519-blake2b" uv.lock || echo "Clean: no Solana transitive deps"
```

Expected: "Clean: no Solana transitive deps"

- [ ] **Step 6: Sync environment and run full test suite**

```bash
uv sync
uv run pytest tests/ -v
```

Expected: All PASS.

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml .python-version uv.lock
git commit -m "chore: remove Solana deps, fix duplicate tomli, unify dev deps, add .python-version"
```

---

### Task 7: Update README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update README**

Replace the entire `README.md` with:

```markdown
# crypto-signer

Encrypted wallet + memory-resident signing service for Python crypto automation.

## What it does

- Encrypts private keys at rest (AES-256-GCM + Argon2id)
- Decrypts only into memory after password entry at startup
- Serves signing requests over Unix domain socket
- Business scripts never hold private keys directly
- Supports EVM (Ethereum, Polygon, BSC, etc.)

## Quick Start

```bash
uv sync

# Initialize
uv run crypto-signer init

# Add a key
uv run crypto-signer add --name my-evm --type evm --key

# Start the signing service
uv run crypto-signer start
```

## Usage in Python

```python
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
```

## Supported Platforms

- Linux (primary target)
- macOS (best-effort)
- Windows 11 (with platform adaptations)

## Security

See SECURITY.md for threat model and security boundaries.
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: update README — remove Solana, use uv commands"
```

---

## Summary of Changes

| Task | Files Modified | What Changed |
|------|---------------|-------------|
| 1 | server.py | Remove SolanaSigner import, `_solana` attr, load/zeroize/dispatch, simplify sign_transaction |
| 2 | client.py, test_client.py | Remove `self.solana`, update docstring, delete Solana test |
| 3 | keystore.py | Remove ed25519 from `_derive_address_from_key` and `chain_types` |
| 4 | cli.py | Remove Solana from type map, choices, mnemonic derivation, list display |
| 5 | crypto/solana.py, test_crypto_solana.py | Delete files |
| 6 | pyproject.toml, .python-version, uv.lock | Remove deps, fix tomli, unify dev deps, pin Python, regenerate lock |
| 7 | README.md | Remove Solana mention, use uv commands |
