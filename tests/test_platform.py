import os
import logging
import subprocess
import sys

import pytest
from unittest.mock import patch

from vaultsign.security.platform import (
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


def test_set_file_owner_only_icacls_warns_on_failure(tmp_path, caplog):
    """When win32api is unavailable and icacls fails, a warning is logged."""
    if sys.platform != "win32":
        pytest.skip("Windows-only test")

    from vaultsign.security.platform_win import set_file_owner_only

    f = tmp_path / "test.txt"
    f.write_text("data")

    # patch.dict sets sys.modules entries to None, causing ImportError on
    # `import win32api` inside the function body — no reload needed.
    with patch.dict("sys.modules", {"win32api": None, "win32security": None, "ntsecuritycon": None}), \
         patch("vaultsign.security.platform_win.subprocess.run") as mock_run, \
         caplog.at_level(logging.WARNING):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stderr=b"access denied",
        )
        set_file_owner_only(str(f))

    assert "icacls failed" in caplog.text


def test_set_file_owner_only_warns_missing_username(tmp_path, caplog):
    """When USERNAME env var is missing, a warning is logged."""
    if sys.platform != "win32":
        pytest.skip("Windows-only test")

    from vaultsign.security.platform_win import set_file_owner_only

    f = tmp_path / "test.txt"
    f.write_text("data")

    with patch.dict("sys.modules", {"win32api": None, "win32security": None, "ntsecuritycon": None}), \
         patch.dict(os.environ, {"USERDOMAIN": "", "USERNAME": ""}, clear=False), \
         caplog.at_level(logging.WARNING):
        set_file_owner_only(str(f))

    assert "USERNAME" in caplog.text


def test_lock_memory_sets_virtuallock_argtypes():
    """VirtualLock must have explicit ctypes argtypes for 64-bit correctness."""
    if sys.platform != "win32":
        pytest.skip("Windows-only test")

    import ctypes
    from vaultsign.security.platform_win import lock_memory

    buf = bytearray(64)
    lock_memory(buf)

    kernel32 = ctypes.windll.kernel32
    assert kernel32.VirtualLock.argtypes == [ctypes.c_void_p, ctypes.c_size_t]
    assert kernel32.VirtualLock.restype == ctypes.c_int
