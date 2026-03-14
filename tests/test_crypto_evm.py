# tests/test_crypto_evm.py
import pytest
from unittest.mock import patch

from crypto_signer.crypto.evm import EVMSigner
from crypto_signer.errors import SigningError


# Well-known test private key (DO NOT use in production)
TEST_KEY = bytearray(bytes.fromhex(
    "4c0883a69102937d6231471b5dbb6204fe512961708279f15b0d7e4b2cd53f37"
))
TEST_ADDRESS = "0x864eC9c7662f55Af9f7637162042d9F5b2aDb1dB"


@pytest.fixture
def signer():
    return EVMSigner(bytearray(TEST_KEY))


def test_get_address(signer):
    addr = signer.get_address()
    assert addr.lower() == TEST_ADDRESS.lower()


def test_sign_transaction(signer):
    tx = {
        "to": "0x0000000000000000000000000000000000000000",
        "value": 0,
        "gas": 21000,
        "gasPrice": 1000000000,
        "nonce": 0,
        "chainId": 1,
    }
    result = signer.sign_transaction(tx)
    assert "signed_tx" in result
    assert "tx_hash" in result
    assert result["signed_tx"].startswith("0x")


def test_sign_message(signer):
    result = signer.sign_message("Hello World")
    assert "signature" in result
    assert result["signature"].startswith("0x")


def test_sign_typed_data(signer):
    domain = {
        "name": "Test",
        "version": "1",
        "chainId": 1,
    }
    types = {
        "Mail": [
            {"name": "contents", "type": "string"},
        ],
    }
    value = {"contents": "Hello"}
    result = signer.sign_typed_data(domain, types, value)
    assert "signature" in result


def test_sign_transaction_propagates_unexpected_error(signer):
    """RuntimeError (not in narrowed set) should propagate, not be wrapped."""
    with patch.object(signer._account, "sign_transaction", side_effect=RuntimeError("unexpected")):
        with pytest.raises(RuntimeError):
            signer.sign_transaction({"to": "0x0", "value": 0, "gas": 21000, "gasPrice": 1000000000, "nonce": 0, "chainId": 1})


def test_sign_message_wraps_value_error(signer):
    """ValueError should be wrapped in SigningError."""
    with patch.object(signer._account, "sign_message", side_effect=ValueError("bad format")):
        with pytest.raises(SigningError, match="bad format"):
            signer.sign_message("test")
