"""High-level process hardening that delegates to platform module."""

import logging
from .platform import harden_process, lock_memory

logger = logging.getLogger(__name__)


def apply_hardening() -> dict:
    result = harden_process()
    for key, value in result.items():
        if key == "core_dump_disabled" and value:
            logger.info("Core dump protection enabled")
        elif key == "swap_warning" and value:
            logger.warning("Swap/pagefile detected — keys may be paged to disk")
    return result


def lock_key_memory(buf: bytearray) -> bool:
    success = lock_memory(buf)
    if success:
        logger.debug("Key memory locked successfully (%d bytes)", len(buf))
    else:
        logger.warning("Could not lock key memory — swap protection unavailable")
    return success
