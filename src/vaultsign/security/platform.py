"""Platform detection and dispatch for security operations."""

import sys

if sys.platform == "win32":
    from .platform_win import (
        lock_memory, set_file_owner_only, harden_process, get_peer_credentials, PLATFORM,
    )
else:
    from .platform_unix import (
        lock_memory, set_file_owner_only, harden_process, get_peer_credentials, PLATFORM,
    )

__all__ = ["lock_memory", "set_file_owner_only", "harden_process", "get_peer_credentials", "PLATFORM"]
