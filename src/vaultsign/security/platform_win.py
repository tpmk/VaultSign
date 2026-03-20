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
        kernel32.VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        kernel32.VirtualLock.restype = ctypes.c_int
        addr = (ctypes.c_char * len(buf)).from_buffer(buf)
        result = kernel32.VirtualLock(ctypes.addressof(addr), len(buf))
        if result == 0:
            logger.warning("VirtualLock failed: error=%d", ctypes.GetLastError())
            return False
        return True
    except (OSError, ValueError, AttributeError, ctypes.ArgumentError) as e:
        logger.warning("VirtualLock unavailable: %s", e)
        return False


def _set_acl_pywin32(path: str) -> None:
    """Set file ACL to owner-only using pywin32 APIs.

    Raises ImportError if pywin32 is not installed.
    Raises pywintypes.error or OSError on ACL operation failure.
    """
    import win32api
    import win32security
    import ntsecuritycon as con

    user_sid = win32security.GetTokenInformation(
        win32security.OpenProcessToken(
            win32api.GetCurrentProcess(), con.TOKEN_QUERY
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


def _set_acl_icacls(path: str) -> bool:
    """Set file ACL to owner-only using icacls.

    Returns True on success, False on failure. Never raises.
    """
    domain = os.environ.get("USERDOMAIN", "")
    username = os.environ.get("USERNAME", "")
    if not username:
        logger.warning(
            "Cannot set file permissions: USERNAME env var not set"
        )
        return False
    qualified = f"{domain}\\{username}" if domain else username
    try:
        result = subprocess.run(
            ["icacls", path, "/inheritance:r", "/grant:r", f"{qualified}:(F)"],
            capture_output=True,
        )
    except OSError as e:
        logger.warning("Failed to launch icacls: %s", e)
        return False
    if result.returncode != 0:
        logger.warning(
            "icacls failed (rc=%d): %s",
            result.returncode,
            result.stderr.decode(errors="replace").strip(),
        )
        return False
    return True


def set_file_owner_only(path: str) -> None:
    """Restrict file access to the current user only.

    Tries pywin32 APIs first, falls back to icacls, then warns on total
    failure. Never raises — callers do not need error handling.
    """
    try:
        _set_acl_pywin32(path)
        return
    except ImportError:
        logger.debug("pywin32 not available, trying icacls")
    except Exception as e:
        logger.warning("pywin32 ACL operation failed: %s; trying icacls", e)

    _set_acl_icacls(path)


def harden_process() -> dict:
    result = {"core_dump_disabled": False, "swap_warning": True}
    logger.warning("Core dump protection not available on Windows")
    logger.warning("Windows pagefile is always present. Private keys could be written to pagefile.")
    return result


def get_peer_credentials(sock) -> int | None:
    logger.debug("Peer credential verification not available on Windows")
    return None
