"""Integration tests: full lifecycle with server + client."""

import json
import os
import socket
import threading
import time

import pytest

from vaultsign.client import SignerClient
from vaultsign.config import Config
from vaultsign.keystore import Keystore
from vaultsign.server import SignerServer
from vaultsign.errors import SignerLockedError


TEST_EVM_KEY = bytes.fromhex(
    "4c0883a69102937d6231471b5dbb6204fe512961708279f15b0d7e4b2cd53f37"
)
TEST_EVM_ADDRESS = "0x864eC9c7662f55Af9f7637162042d9F5b2aDb1dB"
TEST_PASSWORD = "integration_test_pw"
TEST_OPAQUE_KEY = "my-lighter-api-secret-key-value"

from vaultsign import transport
_USE_UNIX = transport.get_transport_mode() == "unix"


@pytest.fixture
def full_env(tmp_path):
    """Full integration environment: keystore + server + client."""
    home = tmp_path / ".vaultsign"
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
    if _USE_UNIX:
        for _ in range(50):
            if os.path.exists(sock_path):
                break
            time.sleep(0.05)
    else:
        # Windows TCP fallback: wait for server to bind and write port file
        for _ in range(50):
            if server.server_address is not None:
                break
            time.sleep(0.05)

    # On both platforms, socket_path triggers the right transport:
    # Unix → AF_UNIX directly; Windows → reads port/token files from same dir
    client = SignerClient(socket_path=sock_path)

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
    from vaultsign.errors import InvalidPasswordError
    with pytest.raises(InvalidPasswordError):
        client.unlock(password="wrong_password_12")


def test_ping(full_env):
    server, client = full_env
    result = client.ping()
    assert result["status"] == "ok"


@pytest.fixture
def full_env_with_opaque(tmp_path):
    """Full integration environment with both EVM and opaque keys."""
    home = tmp_path / ".vaultsign"
    home.mkdir()
    sock_path = str(home / "signer.sock")

    ks = Keystore(str(home / "keystore.json"))
    ks.add_key(
        name="test-evm",
        key_type="secp256k1",
        address=TEST_EVM_ADDRESS,
        private_key=bytearray(TEST_EVM_KEY),
        password=bytearray(TEST_PASSWORD.encode()),
    )
    ks.add_key(
        name="lighter-api",
        key_type="opaque",
        address=None,
        private_key=bytearray(TEST_OPAQUE_KEY.encode("utf-8")),
        password=bytearray(TEST_PASSWORD.encode()),
    )
    ks.save()

    config = Config(
        home_dir=str(home),
        socket_path=sock_path,
        rate_limit=1000,
    )

    server = SignerServer(config)
    server.load_keystore()

    t = threading.Thread(target=server.serve, daemon=True)
    t.start()

    if _USE_UNIX:
        for _ in range(50):
            if os.path.exists(sock_path):
                break
            time.sleep(0.05)
    else:
        for _ in range(50):
            if server.server_address is not None:
                break
            time.sleep(0.05)

    client = SignerClient(socket_path=sock_path)

    yield server, client

    server.shutdown()


def test_get_key_opaque_lifecycle(full_env_with_opaque):
    """End-to-end: add opaque key, unlock, get_key, verify content."""
    server, client = full_env_with_opaque

    # Locked — get_key should fail
    with pytest.raises(SignerLockedError):
        client.get_key("lighter-api")

    # Unlock
    client.unlock(password=TEST_PASSWORD)

    # get_key opaque
    key = client.get_key("lighter-api")
    assert key == TEST_OPAQUE_KEY

    # get_key EVM — now correctly returns hex via key_type metadata
    evm_key = client.get_key("test-evm")
    assert evm_key == TEST_EVM_KEY.hex()

    # Existing sign_transaction still works
    result = client.evm.sign_transaction({
        "to": "0x0000000000000000000000000000000000000000",
        "value": 0,
        "gas": 21000,
        "gasPrice": 1000000000,
        "nonce": 0,
        "chainId": 1,
    })
    assert "signed_tx" in result

    # get_key nonexistent
    from vaultsign.errors import KeyNotFoundError
    with pytest.raises(KeyNotFoundError):
        client.get_key("nonexistent")

    # Lock — get_key should fail again
    client.lock()
    with pytest.raises(SignerLockedError):
        client.get_key("lighter-api")
