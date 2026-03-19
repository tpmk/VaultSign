from vaultsign.errors import (
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
    ErrorCode,
)


def test_all_errors_inherit_from_signer_error():
    errors = [
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
    ]
    for err_cls in errors:
        assert issubclass(err_cls, SignerError)


def test_error_codes_are_unique():
    codes = [e.value for e in ErrorCode]
    assert len(codes) == len(set(codes))


def test_signer_locked_error_has_correct_code():
    err = SignerLockedError("test")
    assert err.code == ErrorCode.SIGNER_LOCKED
    assert err.code.value == 1001


def test_error_to_dict():
    err = SignerLockedError("signer is locked")
    d = err.to_dict()
    assert d == {"code": 1001, "message": "signer is locked"}


def test_error_from_dict():
    d = {"code": 1001, "message": "signer is locked"}
    err = SignerError.from_dict(d)
    assert isinstance(err, SignerLockedError)
    assert str(err) == "signer is locked"


def test_error_repr_does_not_leak_secrets():
    err = SigningError("failed to sign")
    r = repr(err)
    assert "SigningError" in r
    assert "failed to sign" in r


def test_key_not_found_error_code():
    from vaultsign.errors import KeyNotFoundError, ErrorCode
    err = KeyNotFoundError("key 'foo' not found")
    assert err.code == ErrorCode.KEY_NOT_FOUND
    assert err.code.value == 1010
    d = err.to_dict()
    assert d["code"] == 1010
    assert "foo" in d["message"]


def test_key_not_found_error_roundtrip():
    from vaultsign.errors import KeyNotFoundError, SignerError
    err = KeyNotFoundError("not found")
    d = err.to_dict()
    restored = SignerError.from_dict(d)
    assert isinstance(restored, KeyNotFoundError)
