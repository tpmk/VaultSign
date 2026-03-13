# Remove Solana Support & Full uv Integration

**Date:** 2026-03-13
**Status:** Approved

## Goal

Two changes to crypto-signer:

1. Remove Solana chain support entirely — the project becomes EVM-only while retaining the multi-chain abstraction for future extensibility.
2. Adopt uv as the primary environment manager so that `uv sync` is all a new contributor needs.

## Work Stream 1: Remove Solana Support

### Files to Delete

- `src/crypto_signer/crypto/solana.py` — SolanaSigner class (Ed25519 signing via solders)
- `tests/test_crypto_solana.py` — Solana signing unit tests

### Files to Modify

| File | Changes |
|------|---------|
| `src/crypto_signer/cli.py` | Remove `"solana"` from `_TYPE_MAP` and `click.Choice`. Delete `_derive_from_mnemonic` Solana branch (bip_utils import + BIP44 derivation). Remove `"solana"/"ed25519"` branch from `_derive_address`. Fix `list_keys` display logic that falls back to `"solana"` for unknown key types. |
| `src/crypto_signer/server.py` | Remove top-level `from .crypto.solana import SolanaSigner`. Remove `self._solana` attribute, its loading in unlock, its zeroization in lock, and the `"solana"` case in `_get_chain_signer`. |
| `src/crypto_signer/client.py` | Remove `self.solana = _ChainClient(self._send, "solana")`. Update `_ChainClient` docstring (currently says "evm or solana"). Keep `_ChainClient` abstraction and `self.evm`. |
| `src/crypto_signer/keystore.py` | Remove `"ed25519"` branch in `_derive_address_from_key` and its `SolanaSigner` import. Remove `"ed25519": "solana"` from `chain_types` dict in `add_key`. |
| `tests/test_client.py` | Remove any Solana client test cases. |
| `tests/test_integration.py` | Remove Solana signing integration tests. |
| `README.md` | Remove "and Solana" mentions. |

### Dependencies to Remove

- `solders>=0.21` — Solana transaction handling
- `bip-utils>=2.9` — only used for Solana BIP44 derivation; EVM uses `eth-account`'s built-in `Account.from_mnemonic()`

### What Stays

- Multi-chain abstraction (`_ChainClient`, chain routing in server) — preserved for future chain additions.
- `client.evm` sub-client API — unchanged.
- All EVM crypto, tests, and functionality — untouched.

## Work Stream 2: Full uv Integration

### Changes

| Change | Detail |
|--------|--------|
| Add `.python-version` | Pin to `3.12` for the dev environment. Note: `requires-python = ">=3.10"` in pyproject.toml stays — that's the package compatibility range, not the dev pin. |
| Fix duplicate `tomli` | `pyproject.toml` lines 19-20 both list `tomli>=2.0`. Keep only the conditional: `tomli>=2.0; python_version < '3.11'`. |
| Unify dev dependencies | Remove `[project.optional-dependencies].dev` (pytest 7.0). Keep `[dependency-groups].dev` (pytest 9.0.2) as the single source — this is the modern standard and what `uv sync` uses. |
| Update README | Replace `pip install crypto-signer` with `uv sync`. Show `uv run crypto-signer ...` and `uv run pytest`. |
| Regenerate `uv.lock` | After dependency changes, run `uv lock` to refresh. Verify `solders`, `bip-utils`, and their transitive deps are absent. |

## Out of Scope

- Replacing Hatchling build backend — it works fine with uv.
- Adding new chain support.
- Refactoring multi-chain abstraction.
- Further security hardening beyond what's already committed.
- Updating historical design/plan docs (`docs/superpowers/specs/2026-03-11-*`, `docs/superpowers/plans/2026-03-11-*`) — they contain Solana references but serve as historical records.

## Sequencing

Work Stream 1 (Solana removal) modifies `pyproject.toml` dependencies. Work Stream 2 (uv integration) also modifies `pyproject.toml` and regenerates `uv.lock`. All `pyproject.toml` changes should be consolidated before running `uv lock`.
