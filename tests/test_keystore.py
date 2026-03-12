# tests/test_keystore.py
import json

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
