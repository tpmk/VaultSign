"""Windows platform security implementations."""

import ctypes
import logging
import os
import subprocess

logger = logging.getLogger(__name__)

PLATFORM = "windows"


def lock_memory(buf: bytearray) -> bool:
    try:
        kernel32 = ctypes.windll.kernel32
        addr = (ctypes.c_char * len(buf)).from_buffer(buf)
        result = kernel32.VirtualLock(ctypes.addressof(addr), len(buf))
        if result == 0:
            logger.warning("VirtualLock failed: error=%d", ctypes.GetLastError())
            return False
        return True
    except Exception as e:
        logger.warning("VirtualLock unavailable: %s", e)
        return False


def set_file_owner_only(path: str) -> None:
    try:
        import win32security
        import ntsecuritycon as con
        user_sid = win32security.GetTokenInformation(
            win32security.OpenProcessToken(
                win32security.GetCurrentProcess(), con.TOKEN_QUERY
            ),
            win32security.TokenUser,
        )[0]
        dacl = win32security.ACL()
        dacl.AddAccessAllowedAce(
            win32security.ACL_REVISION, con.FILE_ALL_ACCESS, user_sid,
        )
        sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
        sd.SetSecurityDescriptorDacl(True, dacl, False)
        win32security.SetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION, sd)
    except ImportError:
        username = os.environ.get("USERNAME", "")
        if username:
            subprocess.run(
                ["icacls", path, "/inheritance:r", "/grant:r", f"{username}:(F)"],
                capture_output=True, check=False,
            )


def harden_process() -> dict:
    result = {"core_dump_disabled": False, "swap_warning": True}
    logger.warning("Core dump protection not available on Windows")
    logger.warning("Windows pagefile is always present. Private keys could be written to pagefile.")
    return result


def get_peer_credentials(sock) -> int | None:
    logger.debug("Peer credential verification not available on Windows")
    return None
