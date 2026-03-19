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


@pytest.fixture
def server_env_with_opaque(tmp_path):
    """Set up a keystore + config + server with both an EVM key and an opaque key."""
    home = tmp_path / ".crypto-signer"
    home.mkdir()
    ks_path = home / "keystore.json"
    sock_path = str(home / "signer.sock")

    ks = Keystore(str(ks_path))
    evm_key = bytearray(bytes.fromhex(
        "4c0883a69102937d6231471b5dbb6204fe512961708279f15b0d7e4b2cd53f37"
    ))
    ks.add_key(
        name="test-evm",
        key_type="secp256k1",
        address="0x864eC9c7662f55Af9f7637162042d9F5b2aDb1dB",
        private_key=evm_key,
        password=bytearray(b"testpass1234"),
    )
    opaque_key = bytearray(b"my-lighter-secret-key")
    ks.add_key(
        name="lighter-api",
        key_type="opaque",
        address=None,
        private_key=opaque_key,
        password=bytearray(b"testpass1234"),
    )
    ks.save()

    config = Config(
        home_dir=str(home),
        socket_path=sock_path,
        rate_limit=1000,
    )
    return config, str(ks_path), sock_path


@pytest.fixture
def running_server_with_opaque(server_env_with_opaque):
    config, ks_path, sock_path = server_env_with_opaque
    server = SignerServer(config)
    server.load_keystore()

    t = threading.Thread(target=server.serve, daemon=True)
    t.start()

    token = None
    if hasattr(socket, "AF_UNIX"):
        for _ in range(50):
            if os.path.exists(sock_path):
                break
            time.sleep(0.05)
        address = sock_path
    else:
        for _ in range(50):
            if server.server_address is not None:
                break
            time.sleep(0.05)
        address = server.server_address
        token = server._tcp_token

    yield server, address, token

    server.shutdown()


def test_get_key_opaque(running_server_with_opaque):
    import base64
    server, address, token = running_server_with_opaque
    _send_request(address, {
        "version": 1, "id": "gk1", "method": "unlock",
        "params": {"password": "testpass1234"}
    }, token=token)
    resp = _send_request(address, {
        "version": 1, "id": "gk2", "method": "get_key",
        "params": {"name": "lighter-api"}
    }, token=token)
    assert "result" in resp
    decoded = base64.b64decode(resp["result"]["key"])
    assert decoded == b"my-lighter-secret-key"
    assert resp["result"]["name"] == "lighter-api"
    assert resp["result"]["key_type"] == "opaque"
    assert resp["result"]["address"] is None


def test_get_key_evm(running_server_with_opaque):
    server, address, token = running_server_with_opaque
    _send_request(address, {
        "version": 1, "id": "gk3", "method": "unlock",
        "params": {"password": "testpass1234"}
    }, token=token)
    resp = _send_request(address, {
        "version": 1, "id": "gk4", "method": "get_key",
        "params": {"name": "test-evm"}
    }, token=token)
    assert "result" in resp
    assert resp["result"]["name"] == "test-evm"
    assert resp["result"]["key_type"] == "secp256k1"
    assert resp["result"]["address"] == "0x864eC9c7662f55Af9f7637162042d9F5b2aDb1dB"
    assert "key" in resp["result"]


def test_get_key_not_found(running_server_with_opaque):
    server, address, token = running_server_with_opaque
    _send_request(address, {
        "version": 1, "id": "gk5", "method": "unlock",
        "params": {"password": "testpass1234"}
    }, token=token)
    resp = _send_request(address, {
        "version": 1, "id": "gk6", "method": "get_key",
        "params": {"name": "nonexistent"}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1010  # KeyNotFoundError


def test_get_key_when_locked(running_server_with_opaque):
    server, address, token = running_server_with_opaque
    resp = _send_request(address, {
        "version": 1, "id": "gk7", "method": "get_key",
        "params": {"name": "lighter-api"}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1001  # SignerLockedError


def test_get_key_missing_name(running_server_with_opaque):
    server, address, token = running_server_with_opaque
    _send_request(address, {
        "version": 1, "id": "gk8", "method": "unlock",
        "params": {"password": "testpass1234"}
    }, token=token)
    resp = _send_request(address, {
        "version": 1, "id": "gk9", "method": "get_key",
        "params": {}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008  # IPCProtocolError


def test_get_key_rate_limited(tmp_path):
    home = tmp_path / ".crypto-signer"
    home.mkdir()
    ks_path = home / "keystore.json"
    sock_path = str(home / "signer.sock")

    ks = Keystore(str(ks_path))
    opaque_key = bytearray(b"my-lighter-secret-key")
    ks.add_key(
        name="lighter-api",
        key_type="opaque",
        address=None,
        private_key=opaque_key,
        password=bytearray(b"testpass1234"),
    )
    ks.save()

    config = Config(
        home_dir=str(home),
        socket_path=sock_path,
        rate_limit=2,
    )
    server = SignerServer(config)
    server.load_keystore()

    t = threading.Thread(target=server.serve, daemon=True)
    t.start()

    token = None
    if hasattr(socket, "AF_UNIX"):
        for _ in range(50):
            if os.path.exists(sock_path):
                break
            time.sleep(0.05)
        address = sock_path
    else:
        for _ in range(50):
            if server.server_address is not None:
                break
            time.sleep(0.05)
        address = server.server_address
        token = server._tcp_token

    try:
        _send_request(address, {
            "version": 1, "id": "rl1", "method": "unlock",
            "params": {"password": "testpass1234"}
        }, token=token)
        _send_request(address, {
            "version": 1, "id": "rl2", "method": "get_key",
            "params": {"name": "lighter-api"}
        }, token=token)
        _send_request(address, {
            "version": 1, "id": "rl3", "method": "get_key",
            "params": {"name": "lighter-api"}
        }, token=token)
        resp = _send_request(address, {
            "version": 1, "id": "rl4", "method": "get_key",
            "params": {"name": "lighter-api"}
        }, token=token)
        assert "error" in resp
        assert resp["error"]["code"] == 1006  # PolicyViolationError (rate limited)
    finally:
        server.shutdown()


def test_params_as_string_returns_protocol_error(running_server):
    """params must be a dict; a string should return IPCProtocolError."""
    server, address, token = running_server
    resp = _send_request(address, {
        "version": 1, "id": "v1", "method": "ping", "params": "not-a-dict"
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008
    assert "params must be an object" in resp["error"]["message"]


def test_params_as_list_returns_protocol_error(running_server):
    """params as a list should return IPCProtocolError."""
    server, address, token = running_server
    resp = _send_request(address, {
        "version": 1, "id": "v2", "method": "ping", "params": [1, 2, 3]
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008


def test_params_as_null_returns_protocol_error(running_server):
    """params as null should return IPCProtocolError."""
    server, address, token = running_server
    resp = _send_request(address, {
        "version": 1, "id": "v3", "method": "ping", "params": None
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008


def test_unexpected_exception_returns_internal_error(running_server):
    """Unexpected handler exceptions should return 'Internal error'."""
    server, address, token = running_server
    original = server._handle_ping
    def bad_handler(params):
        raise RuntimeError("something went wrong")
    server._handle_ping = bad_handler
    try:
        resp = _send_request(address, {
            "version": 1, "id": "ie1", "method": "ping", "params": {}
        }, token=token)
        assert "error" in resp
        assert resp["error"]["code"] == 1008
        assert "Internal error" in resp["error"]["message"]
    finally:
        server._handle_ping = original


def test_request_too_large_returns_protocol_error(running_server):
    """Oversized requests should return a structured error, not drop the connection."""
    server, address, token = running_server
    # Build a request whose JSON encoding exceeds the default max_request_size
    huge_params = {"data": "x" * (server.config.max_request_size + 1)}
    req = {"version": 1, "id": "rl1", "method": "ping", "params": huge_params}
    if token is not None:
        req["token"] = token
    resp = _send_request(address, req)
    assert "error" in resp
    assert resp["error"]["code"] == 1008
    assert "too large" in resp["error"]["message"].lower()


def _send_raw(address, raw_bytes: bytes, token: str | None = None) -> dict:
    """Send raw bytes to the server and return the parsed JSON response."""
    if isinstance(address, str):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(address)
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(address)
    s.sendall(raw_bytes)
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


def test_non_dict_json_returns_protocol_error(running_server):
    """A JSON value that isn't an object should return a structured error."""
    server, address, token = running_server
    resp = _send_raw(address, b'"just a string"\n')
    assert "error" in resp
    assert resp["error"]["code"] == 1008


def test_unlock_password_must_be_string(running_server):
    server, address, token = running_server
    resp = _send_request(address, {
        "version": 1, "id": "uv1", "method": "unlock",
        "params": {"password": 12345, "timeout": 0}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008


def test_unlock_timeout_must_be_nonneg_integer(running_server):
    server, address, token = running_server
    resp = _send_request(address, {
        "version": 1, "id": "uv2", "method": "unlock",
        "params": {"password": "testpass1234", "timeout": "five"}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008


def test_unlock_timeout_negative_rejected(running_server):
    server, address, token = running_server
    resp = _send_request(address, {
        "version": 1, "id": "uv3", "method": "unlock",
        "params": {"password": "testpass1234", "timeout": -1}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008


def test_sign_transaction_tx_must_be_object(running_server):
    server, address, token = running_server
    _send_request(address, {
        "version": 1, "id": "st0", "method": "unlock",
        "params": {"password": "testpass1234"}
    }, token=token)
    resp = _send_request(address, {
        "version": 1, "id": "st1", "method": "sign_transaction",
        "params": {"chain": "evm", "tx": "not-an-object"}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008


def test_sign_message_message_must_be_string(running_server):
    server, address, token = running_server
    _send_request(address, {
        "version": 1, "id": "sm0", "method": "unlock",
        "params": {"password": "testpass1234"}
    }, token=token)
    resp = _send_request(address, {
        "version": 1, "id": "sm1", "method": "sign_message",
        "params": {"chain": "evm", "message": 12345}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008


def test_get_key_name_must_be_string(running_server):
    server, address, token = running_server
    _send_request(address, {
        "version": 1, "id": "gkv0", "method": "unlock",
        "params": {"password": "testpass1234"}
    }, token=token)
    resp = _send_request(address, {
        "version": 1, "id": "gkv1", "method": "get_key",
        "params": {"name": 123}
    }, token=token)
    assert "error" in resp
    assert resp["error"]["code"] == 1008


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
