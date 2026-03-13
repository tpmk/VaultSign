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
