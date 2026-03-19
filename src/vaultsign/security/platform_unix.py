"""Unix/macOS platform security implementations."""

import ctypes
import ctypes.util
import logging
import os
import stat
import struct
import sys

logger = logging.getLogger(__name__)

PLATFORM = "macos" if sys.platform == "darwin" else "linux"


def lock_memory(buf: bytearray) -> bool:
    try:
        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            return False
        libc = ctypes.CDLL(libc_name, use_errno=True)
        addr = (ctypes.c_char * len(buf)).from_buffer(buf)
        result = libc.mlock(ctypes.addressof(addr), len(buf))
        if result != 0:
            logger.warning("mlock failed: errno=%d", ctypes.get_errno())
            return False
        return True
    except (OSError, ValueError, AttributeError) as e:
        logger.warning("mlock unavailable: %s", e)
        return False


def set_file_owner_only(path: str) -> None:
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def harden_process() -> dict:
    result = {"core_dump_disabled": False, "swap_warning": False}
    try:
        if sys.platform == "linux":
            PR_SET_DUMPABLE = 4
            libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
            libc.prctl(PR_SET_DUMPABLE, 0)
            result["core_dump_disabled"] = True
        elif sys.platform == "darwin":
            import resource
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            result["core_dump_disabled"] = True
    except (OSError, AttributeError) as e:
        logger.warning("Could not disable core dumps: %s", e)
    try:
        if sys.platform == "linux" and os.path.exists("/proc/swaps"):
            with open("/proc/swaps") as f:
                lines = f.readlines()
            if len(lines) > 1:
                logger.warning("Swap is enabled. Private keys could be written to disk.")
                result["swap_warning"] = True
    except OSError as e:
        logger.warning("Could not check swap status: %s", e)
    return result


def get_peer_credentials(sock) -> int | None:
    try:
        if sys.platform == "linux":
            SO_PEERCRED = 17
            cred = sock.getsockopt(
                __import__("socket").SOL_SOCKET, SO_PEERCRED, struct.calcsize("3i")
            )
            pid, uid, gid = struct.unpack("3i", cred)
            return uid
        elif sys.platform == "darwin":
            LOCAL_PEERCRED = 0x002
            cred = sock.getsockopt(0, LOCAL_PEERCRED, struct.calcsize("iih16i"))
            uid = struct.unpack_from("iih", cred)[1]
            return uid
    except (OSError, struct.error):
        return None
    return None
