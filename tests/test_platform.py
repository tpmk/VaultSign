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


def test_set_file_owner_only_pywin32_error_falls_back_to_icacls(tmp_path, caplog):
    """When pywin32 imports succeed but SetFileSecurity raises, fall back to icacls."""
    if sys.platform != "win32":
        pytest.skip("Windows-only test")

    from unittest.mock import MagicMock
    from vaultsign.security.platform_win import set_file_owner_only

    f = tmp_path / "test.txt"
    f.write_text("data")

    # Create a fake pywintypes.error
    class FakePywinError(Exception):
        pass

    mock_win32api = MagicMock()
    mock_win32security = MagicMock()
    mock_ntsecuritycon = MagicMock()
    mock_pywintypes = MagicMock()
    mock_pywintypes.error = FakePywinError
    mock_win32security.SetFileSecurity.side_effect = FakePywinError("access denied")

    with patch.dict("sys.modules", {
        "win32api": mock_win32api,
        "win32security": mock_win32security,
        "ntsecuritycon": mock_ntsecuritycon,
        "pywintypes": mock_pywintypes,
    }), \
         patch("vaultsign.security.platform_win.subprocess.run") as mock_run, \
         caplog.at_level(logging.WARNING):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stderr=b"",
        )
        set_file_owner_only(str(f))

    # Should have fallen back to icacls
    mock_run.assert_called_once()
    cmd = mock_run.call_args[0][0]
    assert cmd[0] == "icacls"


def test_set_file_owner_only_both_methods_fail_no_exception(tmp_path, caplog):
    """When both pywin32 and icacls fail, warn but don't raise."""
    if sys.platform != "win32":
        pytest.skip("Windows-only test")

    from unittest.mock import MagicMock
    from vaultsign.security.platform_win import set_file_owner_only

    f = tmp_path / "test.txt"
    f.write_text("data")

    class FakePywinError(Exception):
        pass

    mock_win32api = MagicMock()
    mock_win32security = MagicMock()
    mock_ntsecuritycon = MagicMock()
    mock_pywintypes = MagicMock()
    mock_pywintypes.error = FakePywinError
    mock_win32security.SetFileSecurity.side_effect = FakePywinError("access denied")

    with patch.dict("sys.modules", {
        "win32api": mock_win32api,
        "win32security": mock_win32security,
        "ntsecuritycon": mock_ntsecuritycon,
        "pywintypes": mock_pywintypes,
    }), \
         patch("vaultsign.security.platform_win.subprocess.run") as mock_run, \
         caplog.at_level(logging.WARNING):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=1, stderr=b"access denied",
        )
        # Should NOT raise
        set_file_owner_only(str(f))

    assert "icacls failed" in caplog.text


def test_set_file_owner_only_pywin32_success_no_icacls(tmp_path):
    """When pywin32 succeeds, icacls should not be called."""
    if sys.platform != "win32":
        pytest.skip("Windows-only test")

    from unittest.mock import MagicMock
    from vaultsign.security.platform_win import set_file_owner_only

    f = tmp_path / "test.txt"
    f.write_text("data")

    mock_win32api = MagicMock()
    mock_win32security = MagicMock()
    mock_ntsecuritycon = MagicMock()
    mock_ntsecuritycon.TOKEN_QUERY = 0x0008
    mock_ntsecuritycon.FILE_ALL_ACCESS = 0x1F01FF

    with patch.dict("sys.modules", {
        "win32api": mock_win32api,
        "win32security": mock_win32security,
        "ntsecuritycon": mock_ntsecuritycon,
    }), \
         patch("vaultsign.security.platform_win.subprocess.run") as mock_run:
        set_file_owner_only(str(f))

    # icacls should NOT have been called
    mock_run.assert_not_called()
