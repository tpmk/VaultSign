# tests/test_client.py
import json
import os
import socket
import sys
import threading
import time

import pytest

from crypto_signer.client import SignerClient, _MAX_RESPONSE
from crypto_signer.errors import SignerLockedError, SignerConnectionError, IPCProtocolError

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


def _one_shot_server(tmp_path, response_bytes):
    """Start a one-shot server that sends raw bytes and returns client kwargs."""
    sock_path = str(tmp_path / "test.sock")

    def serve():
        if _HAS_AF_UNIX:
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(sock_path)
        else:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
            serve.address = srv.getsockname()
        srv.listen(1)
        conn, _ = srv.accept()
        conn.recv(4096)
        if response_bytes is not None:
            conn.sendall(response_bytes)
        conn.close()
        srv.close()

    serve.address = None
    t = threading.Thread(target=serve, daemon=True)
    t.start()

    if _HAS_AF_UNIX:
        for _ in range(50):
            if os.path.exists(sock_path):
                break
            time.sleep(0.05)
        return {"socket_path": sock_path}
    else:
        time.sleep(0.2)
        return {"host": serve.address[0], "port": serve.address[1]}


def test_non_json_response_raises_protocol_error(tmp_path):
    """Non-JSON response from server should raise IPCProtocolError."""
    kwargs = _one_shot_server(tmp_path, b"not-json\n")
    client = SignerClient(**kwargs)
    with pytest.raises(IPCProtocolError):
        client.ping()


def test_empty_response_raises_protocol_error(tmp_path):
    """Empty response (server closes connection) should raise IPCProtocolError."""
    kwargs = _one_shot_server(tmp_path, None)  # close immediately
    client = SignerClient(**kwargs)
    with pytest.raises(IPCProtocolError):
        client.ping()


def test_oversized_response_raises_protocol_error(tmp_path):
    """Response exceeding _MAX_RESPONSE should raise IPCProtocolError."""
    # Send a response larger than the limit (without a newline so client keeps reading)
    oversized = b"x" * (_MAX_RESPONSE + 1)
    kwargs = _one_shot_server(tmp_path, oversized)
    client = SignerClient(**kwargs)
    with pytest.raises(IPCProtocolError, match="too large"):
        client.ping()
