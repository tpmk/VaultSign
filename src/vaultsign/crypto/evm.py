# src/vaultsign/crypto/evm.py
"""EVM signing engine using eth-account."""

from eth_account import Account
from eth_account.messages import encode_defunct, encode_typed_data

from ..errors import SigningError


class EVMSigner:
    """Signs EVM transactions and messages using an in-memory private key."""

    def __init__(self, private_key: bytearray):
        self._key = private_key
        self._account = Account.from_key(bytes(private_key))

    def get_address(self) -> str:
        return self._account.address

    def sign_transaction(self, tx: dict) -> dict:
        """Sign an EVM transaction. Returns {"signed_tx": "0x...", "tx_hash": "0x..."}."""
        try:
            signed = self._account.sign_transaction(tx)
            raw_hex = signed.raw_transaction.hex() if isinstance(signed.raw_transaction, (bytes, bytearray)) else str(signed.raw_transaction)
            tx_hash_hex = signed.hash.hex() if isinstance(signed.hash, (bytes, bytearray)) else str(signed.hash)
            return {
                "signed_tx": raw_hex if raw_hex.startswith("0x") else "0x" + raw_hex,
                "tx_hash": tx_hash_hex if tx_hash_hex.startswith("0x") else "0x" + tx_hash_hex,
            }
        except (ValueError, TypeError, KeyError, AttributeError) as e:
            raise SigningError(f"EVM sign_transaction failed: {e}")

    def sign_message(self, message: str) -> dict:
        """Sign a message (EIP-191). Returns {"signature": "0x..."}."""
        try:
            msg = encode_defunct(text=message)
            signed = self._account.sign_message(msg)
            sig_hex = signed.signature.hex() if isinstance(signed.signature, (bytes, bytearray)) else str(signed.signature)
            return {"signature": sig_hex if sig_hex.startswith("0x") else "0x" + sig_hex}
        except (ValueError, TypeError, KeyError, AttributeError) as e:
            raise SigningError(f"EVM sign_message failed: {e}")

    def sign_typed_data(self, domain: dict, types: dict, value: dict) -> dict:
        """Sign EIP-712 typed data. Returns {"signature": "0x..."}."""
        try:
            msg = encode_typed_data(
                domain_data=domain,
                message_types=types,
                message_data=value,
            )
            signed = self._account.sign_message(msg)
            sig_hex = signed.signature.hex() if isinstance(signed.signature, (bytes, bytearray)) else str(signed.signature)
            return {"signature": sig_hex if sig_hex.startswith("0x") else "0x" + sig_hex}
        except (ValueError, TypeError, KeyError, AttributeError) as e:
            raise SigningError(f"EVM sign_typed_data failed: {e}")

    def zeroize(self) -> None:
        """Zeroize the private key from memory."""
        from ..security.zeroize import zeroize
        zeroize(self._key)
