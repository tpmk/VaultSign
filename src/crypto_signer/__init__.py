"""crypto-signer: Encrypted wallet + memory-resident signing service."""

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
]
