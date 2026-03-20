"""VaultSign: encrypted key vault and memory-resident signing service."""

from .client import SignerClient, KeyInfo
from .errors import (
    SignerError,
    SignerConnectionError,
    SignerLockedError,
    SignerStateError,
    InvalidPasswordError,
    SigningError,
    UnsupportedChainError,
    PolicyViolationError,
    WalletFormatError,
    IPCProtocolError,
    PermissionDeniedError,
    KeyNotFoundError,
)

__all__ = [
    "SignerClient",
    "KeyInfo",
    "SignerError",
    "SignerConnectionError",
    "SignerLockedError",
    "SignerStateError",
    "InvalidPasswordError",
    "SigningError",
    "UnsupportedChainError",
    "PolicyViolationError",
    "WalletFormatError",
    "IPCProtocolError",
    "PermissionDeniedError",
    "KeyNotFoundError",
]
