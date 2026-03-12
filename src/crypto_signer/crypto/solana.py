# src/crypto_signer/crypto/solana.py
"""Solana signing engine using solders."""

import base64

from solders.keypair import Keypair
from solders.transaction import Transaction

from ..errors import SigningError


class SolanaSigner:
    """Signs Solana transactions and messages using an in-memory private key."""

    def __init__(self, private_key: bytearray):
        self._key = private_key
        try:
            if len(private_key) == 32:
                # 32-byte Ed25519 seed (e.g., from mnemonic derivation)
                self._keypair = Keypair.from_seed(bytes(private_key))
            elif len(private_key) == 64:
                # 64-byte keypair (32-byte seed + 32-byte public key)
                self._keypair = Keypair.from_bytes(bytes(private_key))
            else:
                raise SigningError(
                    f"Invalid Solana key length: {len(private_key)}. Expected 32 or 64 bytes."
                )
        except SigningError:
            raise
        except Exception as e:
            raise SigningError(f"Invalid Solana private key: {e}")

    def get_address(self) -> str:
        return str(self._keypair.pubkey())

    def sign_transaction(self, tx_b64: str) -> dict:
        """Sign a serialized Solana transaction (base64).

        Returns {"signed_tx": "<base64>"}.
        """
        try:
            tx_bytes = base64.b64decode(tx_b64)
            tx = Transaction.from_bytes(tx_bytes)
            tx.sign([self._keypair], tx.message.recent_blockhash)
            signed_bytes = bytes(tx)
            return {"signed_tx": base64.b64encode(signed_bytes).decode()}
        except Exception as e:
            raise SigningError(f"Solana sign_transaction failed: {e}")

    def sign_message(self, message_b64: str) -> dict:
        """Sign a raw message (base64).

        Returns {"signature": "<base64>"}.
        """
        try:
            msg_bytes = base64.b64decode(message_b64)
            sig = self._keypair.sign_message(msg_bytes)
            return {"signature": base64.b64encode(bytes(sig)).decode()}
        except Exception as e:
            raise SigningError(f"Solana sign_message failed: {e}")

    def zeroize(self) -> None:
        """Zeroize the private key from memory."""
        from ..security.zeroize import zeroize
        zeroize(self._key)
