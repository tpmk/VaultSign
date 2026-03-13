# tests/test_server.py
import json
import os
import socket
import sys
import threading
import time

import pytest

from crypto_signer.server import SignerServer
from crypto_signer.config import Config
from crypto_signer.keystore import Keystore


def _send_request(address, request: dict, token: str | None = None) -> dict:
    """Helper: send a JSON request to the server and return the response.

    address is either a socket path (str) for Unix sockets or a (host, port)
    tuple for TCP sockets.
    """
    if token is not None:
        request = {**request, "token": token}
    if isinstance(address, str):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(address)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(address)
    s.sendall((json.dumps(request) + "\n").encode())
    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
        if b"\n" in data:
            break
    s.close()
    return json.loads(data.decode().strip())


@pytest.fixture
def server_env(tmp_path):
    """Set up a keystore + config + server."""
    home = tmp_path / ".crypto-signer"
    home.mkdir()
    ks_path = home / "keystore.json"
    sock_path = str(home / "signer.sock")

    # Create a keystore with a test EVM key
    ks = Keystore(str(ks_path))
    test_key = bytearray(bytes.fromhex(
        "4c0883a69102937d6231471b5dbb6204fe512961708279f15b0d7e4b2cd53f37"
    ))
    ks.add_key(
        name="test-evm",
        key_type="secp256k1",
        address="0x864eC9c7662f55Af9f7637162042d9F5b2aDb1dB",
        private_key=test_key,
        password=bytearray(b"testpass1234"),
    )
    ks.save()

    config = Config(
        home_dir=str(home),
        socket_path=sock_path,
        rate_limit=1000,  # high limit for tests
    )
    return config, str(ks_path), sock_path


@pytest.fixture
def running_server(server_env):
    config, ks_path, sock_path = server_env
    server = SignerServer(config)
    server.load_keystore()

    t = threading.Thread(target=server.serve, daemon=True)
    t.start()

    # Wait for the server to be ready
    token = None
    if hasattr(socket, "AF_UNIX"):
        # Unix: wait for socket file to appear
        for _ in range(50):
            if os.path.exists(sock_path):
                break
            time.sleep(0.05)
        address = sock_path
    else:
        # Windows/TCP: wait for server to bind and get the address
        for _ in range(50):
            if server.server_address is not None:
                break
            time.sleep(0.05)
        address = server.server_address
        token = server._tcp_token

    yield server, address, token

    server.shutdown()


def test_ping(running_server):
    server, address, token = running_server
    resp = _send_request(address, {
        "version": 1, "id": "1", "method": "ping", "params": {}
    }, token=token)
    assert resp["id"] == "1"
    assert resp["result"]["status"] == "ok"


def test_status_when_locked(running_server):
    server, address, token = running_server
    resp = _send_request(address, {
        "version": 1, "id": "2", "method": "status", "params": {}
    }, token=token)
    assert resp["result"]["state"] == "locked"


def test_unlock_and_sign(running_server):
    server, address, token = running_server
    # Unlock
    resp = _send_request(address, {
        "version": 1, "id": "3", "method": "unlock",
        "params": {"password": "testpass1234"}
    }, token=token)
    assert "result" in resp

    # Status should be unlocked
    resp = _send_request(address, {
        "version": 1, "id": "4", "method": "status", "params": {}
    }, token=token)
    assert resp["result"]["state"] == "unlocked"

    # Sign a transaction
    resp = _send_request(address, {
        "version": 1, "id": "5", "method": "sign_transaction",
        "params": {
            "chain": "evm",
            "tx": {
                "to": "0x0000000000000000000000000000000000000000",
                "value": 0,
                "gas": 21000,
                "gasPrice": 1000000000,
                "nonce": 0,
                "chainId": 1,
            }
        }
    }, token=token)
    assert "result" in resp
    assert "signed_tx" in resp["result"]


def test_sign_when_locked_returns_error(running_server):
    server, address, token = running_server
    resp = _send_request(address, {
        "version": 1, "id": "6", "method": "sign_transaction",
        "params": {"chain": "evm", "tx": {}}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1001  # SignerLockedError


def test_lock_after_unlock(running_server):
    server, address, token = running_server
    # Unlock
    _send_request(address, {
        "version": 1, "id": "7", "method": "unlock",
        "params": {"password": "testpass1234"}
    }, token=token)
    # Lock
    resp = _send_request(address, {
        "version": 1, "id": "8", "method": "lock", "params": {}
    }, token=token)
    assert "result" in resp

    # Status should be locked again
    resp = _send_request(address, {
        "version": 1, "id": "9", "method": "status", "params": {}
    }, token=token)
    assert resp["result"]["state"] == "locked"


def test_invalid_method(running_server):
    server, address, token = running_server
    resp = _send_request(address, {
        "version": 1, "id": "10", "method": "nonexistent", "params": {}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008  # IPCProtocolError


def test_tcp_token_auth(server_env):
    """TCP mode requires a valid token; requests without it are rejected."""
    config, ks_path, sock_path = server_env
    server = SignerServer(config)
    server.load_keystore()

    # Force TCP mode
    import crypto_signer.server as server_mod
    original = server_mod._HAS_AF_UNIX
    server_mod._HAS_AF_UNIX = False
    try:
        t = threading.Thread(target=server.serve, daemon=True)
        t.start()
        for _ in range(50):
            if server.server_address is not None:
                break
            time.sleep(0.05)
        address = server.server_address

        # Request WITHOUT token should be rejected
        resp = _send_request(address, {
            "version": 1, "id": "t1", "method": "ping", "params": {}
        })
        assert "error" in resp
        assert resp["error"]["code"] == 1009  # PermissionDeniedError

        # Request WITH correct token should succeed
        token = open(config.token_path).read().strip()
        resp = _send_request(address, {
            "version": 1, "id": "t2", "method": "ping", "params": {},
            "token": token,
        })
        assert "result" in resp
        assert resp["result"]["status"] == "ok"
    finally:
        server.shutdown()
        server_mod._HAS_AF_UNIX = original
