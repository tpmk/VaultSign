import sys
from crypto_signer.security.platform import (
    lock_memory, set_file_owner_only, harden_process, get_peer_credentials, PLATFORM,
)


def test_platform_detected():
    if sys.platform == "win32":
        assert PLATFORM == "windows"
    elif sys.platform == "darwin":
        assert PLATFORM == "macos"
    else:
        assert PLATFORM == "linux"


def test_lock_memory_returns_bool():
    buf = bytearray(64)
    result = lock_memory(buf)
    assert isinstance(result, bool)


def test_set_file_owner_only(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("data")
    set_file_owner_only(str(f))


def test_harden_process_returns_dict():
    result = harden_process()
    assert isinstance(result, dict)
    assert "core_dump_disabled" in result
    assert "swap_warning" in result


def test_get_peer_credentials_returns_none_for_bad_socket():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = get_peer_credentials(s)
    s.close()
    assert result is None
