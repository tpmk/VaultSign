from crypto_signer.security.zeroize import zeroize, SecureByteArray


def test_zeroize_bytearray():
    buf = bytearray(b"secret_key_material")
    zeroize(buf)
    assert all(b == 0 for b in buf)
    assert len(buf) == 19


def test_zeroize_empty():
    buf = bytearray(b"")
    zeroize(buf)
    assert len(buf) == 0


def test_secure_bytearray_context_manager():
    with SecureByteArray(b"secret") as s:
        assert bytes(s) == b"secret"
    assert all(b == 0 for b in s)


def test_secure_bytearray_repr_does_not_leak():
    s = SecureByteArray(b"private_key_data")
    r = repr(s)
    assert "private_key_data" not in r
    assert "SecureByteArray" in r


def test_secure_bytearray_str_does_not_leak():
    s = SecureByteArray(b"private_key_data")
    assert "private_key_data" not in str(s)


def test_secure_bytearray_del_zeroizes():
    s = SecureByteArray(b"secret")
    ref = s._data
    s.zeroize()
    assert all(b == 0 for b in ref)
