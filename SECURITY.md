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
