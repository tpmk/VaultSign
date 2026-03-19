"""VaultSign: encrypted key vault and memory-resident signing service."""

from .client import SignerClient
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
