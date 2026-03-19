"""Configuration loading for crypto-signer."""

import sys
from dataclasses import dataclass, field
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


def _default_home() -> str:
    return str(Path.home() / ".crypto-signer")


@dataclass
class Config:
    home_dir: str = field(default_factory=_default_home)
    socket_path: str = ""
    unlock_timeout: int = 0
    disable_core_dump: bool = True
    try_mlock: bool = True
    max_request_size: int = 1048576
    rate_limit: int = 60
    min_password_length: int = 8
    max_unlock_attempts: int = 5

    def __post_init__(self):
        if not self.socket_path:
            self.socket_path = str(Path(self.home_dir) / "signer.sock")

    @property
    def keystore_path(self) -> str:
        return str(Path(self.home_dir) / "keystore.json")

    @property
    def pid_path(self) -> str:
        return str(Path(self.home_dir) / "signer.pid")

    @property
    def port_path(self) -> str:
        return str(Path(self.home_dir) / "signer.port")

    @property
    def token_path(self) -> str:
        return str(Path(self.home_dir) / "signer.token")

    @property
    def config_path(self) -> str:
        return str(Path(self.home_dir) / "config.toml")

    @classmethod
    def from_file(cls, path: str) -> "Config":
        kwargs = {}
        try:
            with open(path, "rb") as f:
                data = tomllib.load(f)
        except (FileNotFoundError, OSError):
            return cls()
        # Set home_dir to config file's parent so __post_init__ derives
        # socket_path, keystore_path, etc. relative to it.
        kwargs["home_dir"] = str(Path(path).parent)
        signer = data.get("signer", {})
        security = data.get("security", {})
        for key in ("socket_path", "unlock_timeout", "disable_core_dump", "try_mlock"):
            if key in signer:
                kwargs[key] = signer[key]
        for key in ("max_request_size", "rate_limit", "min_password_length", "max_unlock_attempts"):
            if key in security:
                kwargs[key] = security[key]
        return cls(**kwargs)

    @classmethod
    def load(cls, home_dir: str | None = None) -> "Config":
        if home_dir:
            config_path = str(Path(home_dir) / "config.toml")
            c = cls.from_file(config_path)
            c.home_dir = home_dir
            if not c.socket_path or c.socket_path.endswith("signer.sock"):
                c.socket_path = str(Path(home_dir) / "signer.sock")
            return c
        return cls.from_file(str(Path(_default_home()) / "config.toml"))
