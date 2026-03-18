# src/crypto_signer/keystore.py
"""Encrypted keystore management.

Handles reading, writing, encrypting, and decrypting keystore.json.
All keys share one password. Each key has independent salt/IV.
"""

import base64
import json
import os
from dataclasses import dataclass

import argon2.low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import InvalidPasswordError, WalletFormatError
from .security.zeroize import SecureByteArray, zeroize

# Argon2id defaults (from spec)
_KDF_PARAMS = {
    "memory_cost": 65536,  # 64 MiB
    "time_cost": 3,
    "parallelism": 4,
}
_SALT_LEN = 16
_IV_LEN = 12
_KEY_LEN = 32  # AES-256


@dataclass
class KeyEntry:
    name: str
    key_type: str
    address: str | None
    # Only populated after decryption:
    private_key: bytearray | None = None

    def __repr__(self) -> str:
        pk_repr = f"bytearray(len={len(self.private_key)})" if self.private_key else "None"
        return f"KeyEntry(name={self.name!r}, key_type={self.key_type!r}, address={self.address!r}, private_key={pk_repr})"


@dataclass
class _EncryptedEntry:
    name: str
    key_type: str
    address: str | None
    salt: bytes
    iv: bytes
    encrypted_key: bytes
    tag: bytes


def _derive_key(password: bytearray, salt: bytes) -> bytearray:
    """Derive a 32-byte key from password using Argon2id."""
    raw = argon2.low_level.hash_secret_raw(
        secret=bytes(password),
        salt=salt,
        time_cost=_KDF_PARAMS["time_cost"],
        memory_cost=_KDF_PARAMS["memory_cost"],
        parallelism=_KDF_PARAMS["parallelism"],
        hash_len=_KEY_LEN,
        type=argon2.low_level.Type.ID,
    )
    return bytearray(raw)


def _encrypt(private_key: bytearray, password: bytearray) -> tuple[bytes, bytes, bytes, bytes]:
    """Encrypt a private key. Returns (salt, iv, ciphertext, tag)."""
    salt = os.urandom(_SALT_LEN)
    iv = os.urandom(_IV_LEN)
    derived = _derive_key(password, salt)
    try:
        aes = AESGCM(bytes(derived))
        # AESGCM.encrypt appends the tag to the ciphertext
        ct_with_tag = aes.encrypt(iv, bytes(private_key), None)
        # Split: last 16 bytes are the GCM tag
        ct = ct_with_tag[:-16]
        tag = ct_with_tag[-16:]
        return salt, iv, ct, tag
    finally:
        zeroize(derived)


def _decrypt(
    salt: bytes, iv: bytes, ct: bytes, tag: bytes, password: bytearray
) -> bytearray:
    """Decrypt a private key. Returns bytearray."""
    derived = _derive_key(password, salt)
    try:
        aes = AESGCM(bytes(derived))
        ct_with_tag = ct + tag
        plaintext = aes.decrypt(iv, ct_with_tag, None)
        return bytearray(plaintext)
    except Exception:
        raise InvalidPasswordError("Decryption failed — wrong password or corrupted keystore")
    finally:
        zeroize(derived)


def _derive_address_from_key(key_type: str, private_key: bytearray) -> str:
    """Derive address from a private key for verification."""
    if key_type == "secp256k1":
        try:
            from .crypto.evm import EVMSigner
            signer = EVMSigner(bytearray(private_key))
            addr = signer.get_address()
            signer.zeroize()
            return addr
        except ImportError:
            return ""
    return ""


class Keystore:
    """Manages encrypted keystore file."""

    def __init__(self, path: str):
        self.path = path
        self.entries: list[_EncryptedEntry] = []

    def add_key(
        self,
        name: str,
        key_type: str,
        address: str | None,
        private_key: bytearray,
        password: bytearray,
    ) -> None:
        """Encrypt and add a key to the keystore."""
        # Name uniqueness check
        for entry in self.entries:
            if entry.name == name:
                raise ValueError(
                    f"A key with name '{name}' already exists."
                )

        # v1: one key per chain type (opaque exempt)
        if key_type != "opaque":
            chain_types = {"secp256k1": "evm"}
            chain = chain_types.get(key_type, key_type)
            for entry in self.entries:
                if entry.key_type == "opaque":
                    continue
                entry_chain = chain_types.get(entry.key_type, entry.key_type)
                if entry_chain == chain:
                    raise ValueError(
                        f"A key for chain type '{chain}' already exists. "
                        "v1 supports one key per chain type."
                    )

        salt, iv, ct, tag = _encrypt(private_key, password)
        zeroize(private_key)

        self.entries.append(
            _EncryptedEntry(
                name=name,
                key_type=key_type,
                address=address,
                salt=salt,
                iv=iv,
                encrypted_key=ct,
                tag=tag,
            )
        )

    def remove_key(self, name: str) -> None:
        """Remove a key by name."""
        self.entries = [e for e in self.entries if e.name != name]

    def list_keys(self) -> list[dict]:
        """List keys (non-sensitive info only)."""
        return [
            {"name": e.name, "key_type": e.key_type, "address": e.address}
            for e in self.entries
        ]

    def decrypt_all(self, password: bytearray) -> list[KeyEntry]:
        """Decrypt all keys with the given password.

        Verifies each decrypted key's derived address matches the stored address.
        """
        results = []
        try:
            for entry in self.entries:
                pk = _decrypt(entry.salt, entry.iv, entry.encrypted_key, entry.tag, password)

                # Verify address matches (spec requirement)
                derived_addr = _derive_address_from_key(entry.key_type, pk)
                if derived_addr and entry.address and derived_addr.lower() != entry.address.lower():
                    zeroize(pk)
                    raise WalletFormatError(
                        f"Address mismatch for key '{entry.name}': "
                        f"expected {entry.address}, derived {derived_addr}. "
                        "Keystore may be corrupted."
                    )

                results.append(
                    KeyEntry(
                        name=entry.name,
                        key_type=entry.key_type,
                        address=entry.address,
                        private_key=pk,
                    )
                )
        except Exception:
            for r in results:
                if r.private_key:
                    zeroize(r.private_key)
            raise
        return results

    def save(self) -> None:
        """Write keystore to disk as JSON with restricted permissions."""
        from .security.platform import set_file_owner_only

        data = {
            "version": 1,
            "kdf": "argon2id",
            "kdf_params": dict(_KDF_PARAMS),
            "keys": [
                {
                    "name": e.name,
                    "key_type": e.key_type,
                    "address": e.address,
                    "cipher": "aes-256-gcm",
                    "salt": base64.b64encode(e.salt).decode(),
                    "encrypted_key": base64.b64encode(e.encrypted_key).decode(),
                    "iv": base64.b64encode(e.iv).decode(),
                    "tag": base64.b64encode(e.tag).decode(),
                }
                for e in self.entries
            ],
        }
        with open(self.path, "w") as f:
            json.dump(data, f, indent=2)
        set_file_owner_only(self.path)

    @classmethod
    def load(cls, path: str) -> "Keystore":
        """Load keystore from disk."""
        try:
            with open(path) as f:
                data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            raise WalletFormatError(f"Cannot read keystore: {e}")

        if data.get("version") != 1:
            raise WalletFormatError(f"Unsupported keystore version: {data.get('version')}")

        ks = cls(path)
        for i, key_data in enumerate(data.get("keys", [])):
            try:
                ks.entries.append(
                    _EncryptedEntry(
                        name=key_data["name"],
                        key_type=key_data["key_type"],
                        address=key_data["address"],
                        salt=base64.b64decode(key_data["salt"]),
                        iv=base64.b64decode(key_data["iv"]),
                        encrypted_key=base64.b64decode(key_data["encrypted_key"]),
                        tag=base64.b64decode(key_data["tag"]),
                    )
                )
            except (KeyError, TypeError, ValueError) as e:
                raise WalletFormatError(
                    f"Invalid key entry at index {i}: {e}"
                ) from e
        return ks
