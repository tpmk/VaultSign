"""Secure input utilities that return zeroizable bytearray."""

import getpass
from .zeroize import SecureByteArray


def secure_getpass(prompt: str = "Password: ") -> SecureByteArray:
    raw = getpass.getpass(prompt)
    result = SecureByteArray(raw.encode("utf-8"))
    del raw
    return result
