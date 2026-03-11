"""Error definitions for crypto-signer.

Error messages MUST NEVER contain plaintext passwords, private keys, or mnemonics.
"""

from enum import IntEnum


class ErrorCode(IntEnum):
    SIGNER_LOCKED = 1001
    SIGNER_STATE = 1002
    INVALID_PASSWORD = 1003
    SIGNING = 1004
    UNSUPPORTED_CHAIN = 1005
    POLICY_VIOLATION = 1006
    WALLET_FORMAT = 1007
    IPC_PROTOCOL = 1008
    PERMISSION_DENIED = 1009


_CODE_TO_CLASS: dict[int, type["SignerError"]] = {}


class SignerError(Exception):
    code: ErrorCode = ErrorCode.SIGNING  # default fallback

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if hasattr(cls, "code") and isinstance(cls.code, ErrorCode):
            _CODE_TO_CLASS[cls.code.value] = cls

    def to_dict(self) -> dict:
        return {"code": self.code.value, "message": str(self)}

    @classmethod
    def from_dict(cls, d: dict) -> "SignerError":
        code = d.get("code", 0)
        message = d.get("message", "unknown error")
        err_cls = _CODE_TO_CLASS.get(code, cls)
        return err_cls(message)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({str(self)!r})"


class SignerConnectionError(SignerError):
    """Client-side only — never serialized over IPC."""

    # Not registered in _CODE_TO_CLASS — this error is client-side only
    code = ErrorCode.SIGNING  # placeholder for consistency

    def __init_subclass__(cls, **kwargs):
        # Skip registration — this error never goes over the wire
        pass


class SignerLockedError(SignerError):
    code = ErrorCode.SIGNER_LOCKED


class SignerStateError(SignerError):
    code = ErrorCode.SIGNER_STATE


class InvalidPasswordError(SignerError):
    code = ErrorCode.INVALID_PASSWORD


class SigningError(SignerError):
    code = ErrorCode.SIGNING


class UnsupportedChainError(SignerError):
    code = ErrorCode.UNSUPPORTED_CHAIN


class PolicyViolationError(SignerError):
    code = ErrorCode.POLICY_VIOLATION


class WalletFormatError(SignerError):
    code = ErrorCode.WALLET_FORMAT


class IPCProtocolError(SignerError):
    code = ErrorCode.IPC_PROTOCOL


class PermissionDeniedError(SignerError):
    code = ErrorCode.PERMISSION_DENIED
