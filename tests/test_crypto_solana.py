# tests/test_crypto_solana.py
import base64

import pytest
from solders.keypair import Keypair
from solders.message import Message
from solders.transaction import Transaction
from solders.system_program import transfer, TransferParams
from solders.pubkey import Pubkey
from solders.hash import Hash

from crypto_signer.crypto.solana import SolanaSigner


@pytest.fixture
def keypair():
    return Keypair()


@pytest.fixture
def signer(keypair):
    raw = bytes(keypair)
    return SolanaSigner(bytearray(raw))


def test_get_address(signer, keypair):
    addr = signer.get_address()
    assert addr == str(keypair.pubkey())


def test_sign_transaction(signer, keypair):
    # Build a simple transfer instruction
    ix = transfer(
        TransferParams(
            from_pubkey=keypair.pubkey(),
            to_pubkey=Pubkey.default(),
            lamports=1000,
        )
    )
    msg = Message.new_with_blockhash(
        [ix], keypair.pubkey(), Hash.default()
    )
    tx = Transaction.new_unsigned(msg)
    tx_bytes = bytes(tx)
    tx_b64 = base64.b64encode(tx_bytes).decode()

    result = signer.sign_transaction(tx_b64)
    assert "signed_tx" in result
    # signed_tx is base64
    decoded = base64.b64decode(result["signed_tx"])
    assert len(decoded) > 0


def test_sign_message(signer):
    msg = base64.b64encode(b"Hello Solana").decode()
    result = signer.sign_message(msg)
    assert "signature" in result
    sig_bytes = base64.b64decode(result["signature"])
    assert len(sig_bytes) == 64  # Ed25519 signature
