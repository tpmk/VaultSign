# tests/test_keystore.py
import json

import pytest

from crypto_signer.errors import WalletFormatError
from crypto_signer.keystore import Keystore, KeyEntry


def test_add_key_and_save(tmp_path):
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="test-evm",
        key_type="secp256k1",
        address="0xabcdef1234567890abcdef1234567890abcdef12",
        private_key=bytearray(b"\x01" * 32),
        password=bytearray(b"testpassword123"),
    )
    ks.save()

    # File should exist and be valid JSON
    data = json.loads(ks_path.read_text())
    assert data["version"] == 1
    assert data["kdf"] == "argon2id"
    assert len(data["keys"]) == 1
    assert data["keys"][0]["name"] == "test-evm"
    assert data["keys"][0]["key_type"] == "secp256k1"
    # encrypted_key should NOT be the raw key
    assert data["keys"][0]["encrypted_key"] != ""


def test_decrypt_key(tmp_path):
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    raw_key = bytearray(b"\xab" * 32)
    ks.add_key(
        name="test-evm",
        key_type="secp256k1",
        address="0xe239cdc5fbe977a8a141B72194D3CF8c41bC5BC6",
        private_key=bytearray(raw_key),  # copy
        password=bytearray(b"testpassword123"),
    )
    ks.save()

    # Load and decrypt
    ks2 = Keystore.load(str(ks_path))
    decrypted = ks2.decrypt_all(bytearray(b"testpassword123"))
    assert len(decrypted) == 1
    assert bytes(decrypted[0].private_key) == b"\xab" * 32


def test_decrypt_wrong_password(tmp_path):
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="test",
        key_type="secp256k1",
        address="0x1234",
        private_key=bytearray(b"\x01" * 32),
        password=bytearray(b"correct_password"),
    )
    ks.save()

    import pytest
    from crypto_signer.errors import InvalidPasswordError

    ks2 = Keystore.load(str(ks_path))
    with pytest.raises(InvalidPasswordError):
        ks2.decrypt_all(bytearray(b"wrong_password"))


def test_add_duplicate_chain_type_rejected(tmp_path):
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="evm-1",
        key_type="secp256k1",
        address="0x1111",
        private_key=bytearray(b"\x01" * 32),
        password=bytearray(b"testpassword123"),
    )

    import pytest
    with pytest.raises(ValueError, match="already exists"):
        ks.add_key(
            name="evm-2",
            key_type="secp256k1",
            address="0x2222",
            private_key=bytearray(b"\x02" * 32),
            password=bytearray(b"testpassword123"),
        )


def test_remove_key(tmp_path):
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="test",
        key_type="secp256k1",
        address="0x1234",
        private_key=bytearray(b"\x01" * 32),
        password=bytearray(b"testpassword123"),
    )
    ks.remove_key("test")
    assert len(ks.entries) == 0


def test_list_keys(tmp_path):
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="my-evm",
        key_type="secp256k1",
        address="0xabc",
        private_key=bytearray(b"\x01" * 32),
        password=bytearray(b"testpassword123"),
    )
    entries = ks.list_keys()
    assert len(entries) == 1
    assert entries[0] == {"name": "my-evm", "key_type": "secp256k1", "address": "0xabc"}


def test_load_keystore_missing_fields(tmp_path):
    """Corrupted keystore with missing fields should raise WalletFormatError."""
    ks_path = tmp_path / "keystore.json"
    ks_path.write_text('{"version": 1, "keys": [{"name": "broken"}]}')
    with pytest.raises(WalletFormatError, match="Invalid key entry"):
        Keystore.load(str(ks_path))


def test_load_keystore_bad_base64(tmp_path):
    """Corrupted keystore with invalid base64 should raise WalletFormatError."""
    ks_path = tmp_path / "keystore.json"
    ks_path.write_text(json.dumps({
        "version": 1,
        "keys": [{
            "name": "bad",
            "key_type": "secp256k1",
            "address": "0x1234",
            "salt": "not-valid-base64!!!",
            "iv": "also-bad",
            "encrypted_key": "nope",
            "tag": "nah",
        }]
    }))
    with pytest.raises(WalletFormatError, match="Invalid key entry"):
        Keystore.load(str(ks_path))


def test_add_opaque_key(tmp_path):
    """Opaque keys can be stored with address=None."""
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="lighter-api",
        key_type="opaque",
        address=None,
        private_key=bytearray(b"some-api-key-string"),
        password=bytearray(b"testpassword123"),
    )
    ks.save()

    data = json.loads(ks_path.read_text())
    assert len(data["keys"]) == 1
    assert data["keys"][0]["name"] == "lighter-api"
    assert data["keys"][0]["key_type"] == "opaque"
    assert data["keys"][0]["address"] is None


def test_decrypt_opaque_key(tmp_path):
    """Opaque keys can be decrypted and return original bytes."""
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    original = b"my-secret-lighter-api-key-12345"
    ks.add_key(
        name="lighter-api",
        key_type="opaque",
        address=None,
        private_key=bytearray(original),
        password=bytearray(b"testpassword123"),
    )
    ks.save()

    ks2 = Keystore.load(str(ks_path))
    decrypted = ks2.decrypt_all(bytearray(b"testpassword123"))
    assert len(decrypted) == 1
    assert decrypted[0].key_type == "opaque"
    assert decrypted[0].address is None
    assert bytes(decrypted[0].private_key) == original


def test_multiple_opaque_keys_allowed(tmp_path):
    """Multiple opaque keys with different names are allowed."""
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="lighter-main",
        key_type="opaque",
        address=None,
        private_key=bytearray(b"key1"),
        password=bytearray(b"testpassword123"),
    )
    ks.add_key(
        name="lighter-sub",
        key_type="opaque",
        address=None,
        private_key=bytearray(b"key2"),
        password=bytearray(b"testpassword123"),
    )
    assert len(ks.entries) == 2


def test_duplicate_name_rejected(tmp_path):
    """Adding a key with a duplicate name raises ValueError."""
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="my-key",
        key_type="opaque",
        address=None,
        private_key=bytearray(b"key1"),
        password=bytearray(b"testpassword123"),
    )
    with pytest.raises(ValueError, match="name.*already exists"):
        ks.add_key(
            name="my-key",
            key_type="opaque",
            address=None,
            private_key=bytearray(b"key2"),
            password=bytearray(b"testpassword123"),
        )


def test_opaque_and_evm_coexist(tmp_path):
    """Opaque and secp256k1 keys can coexist in the same keystore."""
    ks_path = tmp_path / "keystore.json"
    ks = Keystore(str(ks_path))
    ks.add_key(
        name="my-evm",
        key_type="secp256k1",
        address="0x1a642f0E3c3aF545E7AcBD38b07251B3990914F1",
        private_key=bytearray(b"\x01" * 32),
        password=bytearray(b"testpassword123"),
    )
    ks.add_key(
        name="lighter-api",
        key_type="opaque",
        address=None,
        private_key=bytearray(b"lighter-secret"),
        password=bytearray(b"testpassword123"),
    )
    ks.save()

    ks2 = Keystore.load(str(ks_path))
    decrypted = ks2.decrypt_all(bytearray(b"testpassword123"))
    assert len(decrypted) == 2
    types = {d.key_type for d in decrypted}
    assert types == {"secp256k1", "opaque"}
