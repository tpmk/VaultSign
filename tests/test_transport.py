"""Tests for transport mode selection policy."""

import socket
import types
from unittest.mock import patch

from vaultsign.transport import get_transport_mode


def test_windows_always_tcp_even_with_af_unix():
    """Windows must use TCP regardless of AF_UNIX availability."""
    mock_socket = types.ModuleType("socket")
    mock_socket.AF_UNIX = 1
    with patch("vaultsign.transport.sys") as mock_sys, \
         patch("vaultsign.transport.socket", mock_socket):
        mock_sys.platform = "win32"
        assert get_transport_mode() == "tcp"


def test_linux_with_af_unix_uses_unix():
    """Linux with AF_UNIX should prefer Unix sockets."""
    mock_socket = types.ModuleType("socket")
    mock_socket.AF_UNIX = 1
    with patch("vaultsign.transport.sys") as mock_sys, \
         patch("vaultsign.transport.socket", mock_socket):
        mock_sys.platform = "linux"
        assert get_transport_mode() == "unix"


def test_no_af_unix_falls_back_to_tcp():
    """Any platform without AF_UNIX should fall back to TCP."""
    mock_socket = types.ModuleType("socket")
    with patch("vaultsign.transport.sys") as mock_sys, \
         patch("vaultsign.transport.socket", mock_socket):
        mock_sys.platform = "linux"
        assert get_transport_mode() == "tcp"
