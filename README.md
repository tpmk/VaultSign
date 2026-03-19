# VaultSign

Encrypted key vault and memory-resident signing service for Python crypto automation.

## What it does

- Encrypts private keys at rest (AES-256-GCM + Argon2id)
- Decrypts only into memory after password entry at startup
- Serves signing requests over Unix domain socket
- Business scripts never hold private keys directly
- Supports EVM (Ethereum, Polygon, BSC, etc.)
- Keeps the signing boundary local so private keys are harder to leak through scripts, config files, or repo commits

## Quick Start

```bash
uv sync

# Initialize
uv run vaultsign init

# Add a key
uv run vaultsign add --name my-evm --type evm --key

# Start the signing service
uv run vaultsign start
```

## Usage in Python

```python
from vaultsign import SignerClient

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

The Python import path is `vaultsign`.

## Supported Platforms

- Linux (primary target)
- macOS (best-effort)
- Windows 11 (with platform adaptations)

## Security

See SECURITY.md for threat model and security boundaries.
