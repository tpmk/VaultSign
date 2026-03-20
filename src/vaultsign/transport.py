"""Transport mode selection policy.

Windows always uses TCP with token-based auth.
Other platforms prefer Unix domain sockets when available.
"""

import socket
import sys
from typing import Literal


def get_transport_mode() -> Literal["unix", "tcp"]:
    """Return the transport mode for the current platform.

    Windows always uses TCP with token auth.
    Other platforms prefer Unix domain sockets when available.
    """
    if sys.platform == "win32":
        return "tcp"
    if hasattr(socket, "AF_UNIX"):
        return "unix"
    return "tcp"
