# tests/test_client.py
import json
import os
import socket
import sys
import threading
import time

import pytest

from crypto_signer.client import SignerClient
from crypto_signer.errors import SignerLockedError, SignerConnectionError

_HAS_AF_UNIX = hasattr(socket, "AF_UNIX")


@pytest.fixture
def mock_server(tmp_path):
    """A minimal mock server that responds to IPC requests."""
    sock_path = str(tmp_path / "test.sock")
    responses = {}

    def set_response(method, result=None, error=None):
        responses[method] = (result, error)

    def server_loop():
        if _HAS_AF_UNIX:
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(sock_path)
        else:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            server_loop.address = srv.getsockname()
        srv.listen(5)
        srv.settimeout(1.0)

        while getattr(server_loop, "running", True):
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue

            data = conn.recv(4096)
            req = json.loads(data.decode().strip())
            method = req.get("method", "")
            req_id = req.get("id")

            result, error = responses.get(method, ({"status": "ok"}, None))
            if error:
                resp = {"id": req_id, "error": error}
            else:
                resp = {"id": req_id, "result": result}

            conn.sendall((json.dumps(resp) + "\n").encode())
            conn.close()

        srv.close()
        if _HAS_AF_UNIX and os.path.exists(sock_path):
            os.unlink(sock_path)

    server_loop.running = True
    server_loop.address = None
    t = threading.Thread(target=server_loop, daemon=True)
    t.start()

    if _HAS_AF_UNIX:
        for _ in range(50):
            if os.path.exists(sock_path):
                break
            time.sleep(0.05)
        yield sock_path, set_response
    else:
        # Wait for TCP server to be ready
        time.sleep(0.2)
        yield server_loop.address, set_response

    server_loop.running = False
    t.join(timeout=3)


def _make_client(address):
    """Create a SignerClient for either Unix socket or TCP address."""
    if isinstance(address, str):
        return SignerClient(socket_path=address)
    else:
        return SignerClient(host=address[0], port=address[1])


def test_ping(mock_server):
    address, set_response = mock_server
    set_response("ping", {"status": "ok"})
    client = _make_client(address)
    result = client.ping()
    assert result["status"] == "ok"


def test_status(mock_server):
    address, set_response = mock_server
    set_response("status", {"state": "locked", "uptime": 42})
    client = _make_client(address)
    result = client.status()
    assert result["state"] == "locked"


def test_evm_get_address(mock_server):
    address, set_response = mock_server
    set_response("get_address", {"address": "0x1234"})
    client = _make_client(address)
    addr = client.evm.get_address()
    assert addr == "0x1234"


def test_evm_sign_transaction(mock_server):
    address, set_response = mock_server
    set_response("sign_transaction", {"signed_tx": "0xabc", "tx_hash": "0xdef"})
    client = _make_client(address)
    result = client.evm.sign_transaction({"to": "0x0", "value": 0})
    assert result["signed_tx"] == "0xabc"


def test_solana_get_address(mock_server):
    address, set_response = mock_server
    set_response("get_address", {"address": "SoL123"})
    client = _make_client(address)
    addr = client.solana.get_address()
    assert addr == "SoL123"


def test_error_response_raises(mock_server):
    address, set_response = mock_server
    set_response("sign_transaction", error={"code": 1001, "message": "locked"})
    client = _make_client(address)
    with pytest.raises(SignerLockedError):
        client.evm.sign_transaction({})


def test_connection_error():
    client = SignerClient(host="127.0.0.1", port=1)  # port 1 should refuse connection
    with pytest.raises(SignerConnectionError):
        client.ping()
