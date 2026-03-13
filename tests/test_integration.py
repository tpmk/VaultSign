"""Integration tests: full lifecycle with server + client."""

import json
import os
import socket
import threading
import time

import pytest

from crypto_signer.client import SignerClient
from crypto_signer.config import Config
from crypto_signer.keystore import Keystore
from crypto_signer.server import SignerServer
from crypto_signer.errors import SignerLockedError


TEST_EVM_KEY = bytes.fromhex(
    "4c0883a69102937d6231471b5dbb6204fe512961708279f15b0d7e4b2cd53f37"
)
TEST_EVM_ADDRESS = "0x864eC9c7662f55Af9f7637162042d9F5b2aDb1dB"
TEST_PASSWORD = "integration_test_pw"

_HAS_AF_UNIX = hasattr(socket, "AF_UNIX")


@pytest.fixture
def full_env(tmp_path):
    """Full integration environment: keystore + server + client."""
    home = tmp_path / ".crypto-signer"
    home.mkdir()
    sock_path = str(home / "signer.sock")

    # Create keystore
    ks = Keystore(str(home / "keystore.json"))
    ks.add_key(
        name="test-evm",
        key_type="secp256k1",
        address=TEST_EVM_ADDRESS,
        private_key=bytearray(TEST_EVM_KEY),
        password=bytearray(TEST_PASSWORD.encode()),
    )
    ks.save()

    # Create config
    config = Config(
        home_dir=str(home),
        socket_path=sock_path,
        rate_limit=1000,
    )

    # Start server
    server = SignerServer(config)
    server.load_keystore()

    t = threading.Thread(target=server.serve, daemon=True)
    t.start()

    # Wait for server to be ready
    if _HAS_AF_UNIX:
        for _ in range(50):
            if os.path.exists(sock_path):
                break
            time.sleep(0.05)
        client = SignerClient(socket_path=sock_path)
    else:
        # Windows TCP fallback: wait for server_address to be set
        for _ in range(50):
            if server.server_address is not None:
                break
            time.sleep(0.05)
        host, port = server.server_address
        client = SignerClient(host=host, port=port)

    yield server, client

    server.shutdown()


def test_full_lifecycle(full_env):
    server, client = full_env

    # 1. Should be locked initially
    status = client.status()
    assert status["state"] == "locked"

    # 2. Signing should fail when locked
    with pytest.raises(SignerLockedError):
        client.evm.sign_transaction({})

    # 3. Unlock
    client.unlock(password=TEST_PASSWORD)
    status = client.status()
    assert status["state"] == "unlocked"

    # 4. Get address
    addr = client.evm.get_address()
    assert addr.lower() == TEST_EVM_ADDRESS.lower()

    # 5. Sign a transaction
    result = client.evm.sign_transaction({
        "to": "0x0000000000000000000000000000000000000000",
        "value": 0,
        "gas": 21000,
        "gasPrice": 1000000000,
        "nonce": 0,
        "chainId": 1,
    })
    assert "signed_tx" in result
    assert "tx_hash" in result

    # 6. Sign a message
    result = client.evm.sign_message("Hello Integration Test")
    assert "signature" in result

    # 7. Lock
    client.lock()
    status = client.status()
    assert status["state"] == "locked"

    # 8. Should fail again after locking
    with pytest.raises(SignerLockedError):
        client.evm.sign_transaction({})

    # 9. Re-unlock and verify
    client.unlock(password=TEST_PASSWORD)
    addr = client.evm.get_address()
    assert addr.lower() == TEST_EVM_ADDRESS.lower()


def test_wrong_password(full_env):
    server, client = full_env
    from crypto_signer.errors import InvalidPasswordError
    with pytest.raises(InvalidPasswordError):
        client.unlock(password="wrong_password_12")


def test_ping(full_env):
    server, client = full_env
    result = client.ping()
    assert result["status"] == "ok"
