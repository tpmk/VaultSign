"""Secure memory zeroization utilities."""


def zeroize(buf: bytearray) -> None:
    """Overwrite every byte in buf with zeros."""
    for i in range(len(buf)):
        buf[i] = 0


class SecureByteArray:
    """A bytearray wrapper that zeroizes on cleanup."""

    def __init__(self, data: bytes | bytearray = b""):
        if isinstance(data, bytearray):
            self._data = data
        else:
            self._data = bytearray(data)

    def __enter__(self) -> bytearray:
        return self._data

    def __exit__(self, *args) -> None:
        self.zeroize()

    def zeroize(self) -> None:
        zeroize(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def __bytes__(self) -> bytes:
        return bytes(self._data)

    def __repr__(self) -> str:
        return f"SecureByteArray(len={len(self._data)})"

    def __str__(self) -> str:
        return f"SecureByteArray(len={len(self._data)})"

    def __del__(self) -> None:
        self.zeroize()
