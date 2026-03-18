"""CLI entry point for crypto-signer."""

import json
import logging
import os
import signal
import sys
import threading

import click

from .config import Config
from .errors import WalletFormatError
from .keystore import Keystore
from .security.zeroize import zeroize


def _get_config(home: str | None) -> Config:
    if home:
        return Config.load(home_dir=home)
    return Config.load()


def _get_or_create_keystore(config: Config) -> Keystore:
    try:
        return Keystore.load(config.keystore_path)
    except (WalletFormatError, FileNotFoundError):
        return Keystore(config.keystore_path)


def _derive_address(key_type: str, private_key: bytearray) -> str:
    """Derive address from private key for verification."""
    if key_type in ("evm", "secp256k1"):
        from .crypto.evm import EVMSigner
        signer = EVMSigner(bytearray(private_key))  # copy
        addr = signer.get_address()
        signer.zeroize()
        return addr
    raise click.ClickException(f"Unsupported type: {key_type}")


_TYPE_MAP = {"evm": "secp256k1"}


def _check_stale_pid(config: Config) -> None:
    """Check for stale PID file and clean up or abort."""
    if not os.path.exists(config.pid_path):
        return
    try:
        with open(config.pid_path) as f:
            pid = int(f.read().strip())
    except (ValueError, OSError):
        os.unlink(config.pid_path)
        return
    try:
        os.kill(pid, 0)
    except PermissionError:
        # Process exists but inaccessible — treat as alive
        raise click.ClickException(f"Signer already running (PID {pid})")
    except OSError:
        # Process does not exist — clean up stale PID file
        os.unlink(config.pid_path)
        return
    # os.kill succeeded — process is alive
    raise click.ClickException(f"Signer already running (PID {pid})")


@click.group()
def main():
    """crypto-signer: Encrypted wallet + memory-resident signing service."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


@main.command()
@click.option("--home", default=None, help="Override home directory")
def init(home):
    """Initialize ~/.crypto-signer/ directory."""
    config = _get_config(home)
    os.makedirs(config.home_dir, exist_ok=True)

    # Create default config.toml if it doesn't exist
    config_path = config.config_path
    if not os.path.exists(config_path):
        with open(config_path, "w") as f:
            f.write(
                "[signer]\n"
                "# socket_path = \"~/.crypto-signer/signer.sock\"\n"
                "# unlock_timeout = 0\n"
                "# disable_core_dump = true\n"
                "# try_mlock = true\n"
                "\n"
                "[security]\n"
                "# max_request_size = 1048576\n"
                "# rate_limit = 60\n"
                "# min_password_length = 8\n"
                "# max_unlock_attempts = 5\n"
            )

    # Create empty keystore if it doesn't exist
    if not os.path.exists(config.keystore_path):
        ks = Keystore(config.keystore_path)
        ks.save()

    click.echo(f"Initialized {config.home_dir}")


@main.command()
@click.option("--name", required=True, help="Key name")
@click.option("--type", "key_type", required=False, default=None,
              type=click.Choice(["evm", "opaque"]), help="Key type (auto-detected if omitted)")
@click.option("--key", "import_key", is_flag=True, help="Import private key")
@click.option("--mnemonic", "import_mnemonic", is_flag=True, help="Import from mnemonic")
@click.option("--home", default=None, help="Override home directory")
def add(name, key_type, import_key, import_mnemonic, home):
    """Add a key to the keystore."""
    if not import_key and not import_mnemonic:
        raise click.ClickException("Specify --key or --mnemonic")

    if import_mnemonic and key_type == "opaque":
        raise click.ClickException("Mnemonic import is not supported for opaque keys")

    config = _get_config(home)
    ks = _get_or_create_keystore(config)

    if import_mnemonic:
        mnemonic = click.prompt("Enter mnemonic phrase", hide_input=True)
        raw_bytes = _derive_from_mnemonic(mnemonic, "evm")
        del mnemonic
        internal_type = "secp256k1"
        address = _derive_address("evm", raw_bytes)
    elif key_type == "opaque":
        raw_input = click.prompt("Enter private key", hide_input=True)
        raw_bytes = bytearray(raw_input.encode("utf-8"))
        del raw_input
        internal_type = "opaque"
        address = None
    elif key_type == "evm":
        raw_hex = click.prompt("Enter private key", hide_input=True)
        raw_bytes = bytearray(bytes.fromhex(raw_hex.strip().removeprefix("0x")))
        address = _derive_address("evm", raw_bytes)
        internal_type = "secp256k1"
    else:
        # Auto-detect: try EVM first, fall back to opaque
        raw_input = click.prompt("Enter private key", hide_input=True)
        try:
            raw_bytes = bytearray(bytes.fromhex(raw_input.strip().removeprefix("0x")))
            address = _derive_address("evm", raw_bytes)
            internal_type = "secp256k1"
        except Exception:
            raw_bytes = bytearray(raw_input.encode("utf-8"))
            internal_type = "opaque"
            address = None
            click.echo("Warning: Cannot derive address; storing as opaque key.")
        del raw_input

    password_str = click.prompt("Enter password", hide_input=True)
    confirm_str = click.prompt("Confirm password", hide_input=True)

    if password_str != confirm_str:
        zeroize(raw_bytes)
        raise click.ClickException("Passwords do not match")

    if len(password_str) < config.min_password_length:
        zeroize(raw_bytes)
        raise click.ClickException(
            f"Password must be at least {config.min_password_length} characters"
        )

    password = bytearray(password_str.encode("utf-8"))
    del password_str, confirm_str

    try:
        ks.add_key(
            name=name,
            key_type=internal_type,
            address=address,
            private_key=raw_bytes,
            password=password,
        )
        ks.save()
    finally:
        zeroize(password)

    if address:
        click.echo(f"Key '{name}' added. Type: {internal_type}, Address: {address}")
    else:
        click.echo(f"Key '{name}' added. Type: {internal_type}")


def _derive_from_mnemonic(mnemonic: str, key_type: str) -> bytearray:
    """Derive a private key from a mnemonic phrase using BIP-44 paths.

    EVM: m/44'/60'/0'/0/0
    """
    try:
        if key_type == "evm":
            from eth_account import Account
            Account.enable_unaudited_hdwallet_features()
            acct = Account.from_mnemonic(mnemonic, account_path="m/44'/60'/0'/0/0")
            return bytearray(acct.key)
        else:
            raise click.ClickException(f"Unsupported key type for mnemonic: {key_type}")
    except click.ClickException:
        raise
    except Exception as e:
        raise click.ClickException(f"Mnemonic derivation failed: {e}")


@main.command("list")
@click.option("--home", default=None, help="Override home directory")
def list_keys(home):
    """List stored keys."""
    config = _get_config(home)
    try:
        ks = Keystore.load(config.keystore_path)
    except WalletFormatError:
        click.echo("No keystore found. Run 'crypto-signer init' first.")
        return

    keys = ks.list_keys()
    if not keys:
        click.echo("No keys stored.")
        return

    reverse_type = {v: k for k, v in _TYPE_MAP.items()}
    for k in keys:
        chain = reverse_type.get(k["key_type"], k["key_type"])
        click.echo(f"  {k['name']}  [{chain}]  {k['address']}")


@main.command()
@click.option("--name", required=True, help="Key name to remove")
@click.option("--home", default=None, help="Override home directory")
def remove(name, home):
    """Remove a key from the keystore."""
    config = _get_config(home)
    ks = Keystore.load(config.keystore_path)
    ks.remove_key(name)
    ks.save()
    click.echo(f"Key '{name}' removed.")


@main.command()
@click.option("-d", "daemon", is_flag=True, help="Run in background")
@click.option("--home", default=None, help="Override home directory")
def start(daemon, home):
    """Start the signing service."""
    from .server import SignerServer
    from .security.harden import apply_hardening

    config = _get_config(home)
    _check_stale_pid(config)
    server = SignerServer(config)
    server.load_keystore()

    # Prompt for password
    password_str = click.prompt("Enter password to unlock", hide_input=True)
    password = bytearray(password_str.encode("utf-8"))
    del password_str

    try:
        server.unlock(password, config.unlock_timeout)
    except Exception as e:
        raise click.ClickException(str(e))

    click.echo("Signer unlocked and ready.")

    if daemon:
        if sys.platform == "win32":
            _start_daemon_windows(server, config)
            return
        else:
            _start_daemon_unix(server, config)
            return

    # Foreground mode
    apply_hardening()

    def _signal_handler(sig, frame):
        click.echo("\nShutting down...")
        server.shutdown()

    signal.signal(signal.SIGINT, _signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _signal_handler)

    server.serve()


def _daemon_cleanup_handler(config, server):
    """Return a signal handler that cleans up PID file and shuts down server."""
    def handler(sig, frame):
        if server is not None:
            server.shutdown()
        if os.path.exists(config.pid_path):
            os.unlink(config.pid_path)
    return handler


def _start_daemon_unix(server, config):
    """Fork to background on Unix."""
    pid = os.fork()
    if pid > 0:
        with open(config.pid_path, "w") as f:
            f.write(str(pid))
        server.lock()
        click.echo(f"Daemon started (PID {pid})")
        return
    os.setsid()
    handler = _daemon_cleanup_handler(config, server)
    signal.signal(signal.SIGTERM, handler)
    signal.signal(signal.SIGINT, handler)
    from .security.harden import apply_hardening
    apply_hardening()
    server.serve()


def _start_daemon_windows(server, config):
    """Start daemon on Windows."""
    from .security.harden import apply_hardening
    apply_hardening()

    with open(config.pid_path, "w") as f:
        f.write(str(os.getpid()))

    click.echo(f"Daemon started (PID {os.getpid()})")

    t = threading.Thread(target=server.serve, daemon=False)
    t.start()

    try:
        import ctypes
        ctypes.windll.kernel32.FreeConsole()
    except Exception:
        pass

    try:
        t.join()
    finally:
        server.shutdown()
        if os.path.exists(config.pid_path):
            os.unlink(config.pid_path)


@main.command()
@click.option("--home", default=None, help="Override home directory")
def stop(home):
    """Stop the signing service."""
    from .client import SignerClient
    config = _get_config(home)
    try:
        client = SignerClient(socket_path=config.socket_path)
        client._send("shutdown")
        if os.path.exists(config.pid_path):
            os.unlink(config.pid_path)
        click.echo("Signer stopped.")
    except Exception as e:
        if os.path.exists(config.pid_path):
            with open(config.pid_path) as f:
                pid = int(f.read().strip())
            try:
                os.kill(pid, signal.SIGTERM)
                os.unlink(config.pid_path)
                click.echo(f"Sent SIGTERM to PID {pid}")
            except OSError as e2:
                click.echo(f"Could not stop: {e2}")
        else:
            click.echo(f"Could not connect: {e}")


@main.command()
@click.option("--home", default=None, help="Override home directory")
def status(home):
    """Show service status."""
    from .client import SignerClient
    config = _get_config(home)
    try:
        client = SignerClient(socket_path=config.socket_path)
        result = client.status()
        click.echo(f"State: {result['state']}")
        click.echo(f"Uptime: {result.get('uptime', 0)}s")
        if "ttl_remaining" in result:
            click.echo(f"TTL remaining: {result['ttl_remaining']}s")
    except Exception as e:
        click.echo(f"Service not running ({e})")


@main.command()
@click.option("--timeout", default=0, help="Auto-lock timeout in seconds (0=permanent)")
@click.option("--home", default=None, help="Override home directory")
def unlock(timeout, home):
    """Unlock the signing service."""
    from .client import SignerClient
    config = _get_config(home)
    password = click.prompt("Enter password", hide_input=True)
    try:
        client = SignerClient(socket_path=config.socket_path)
        client.unlock(password=password, timeout=timeout)
        click.echo("Signer unlocked.")
    except Exception as e:
        raise click.ClickException(str(e))


@main.command()
@click.option("--home", default=None, help="Override home directory")
def lock(home):
    """Lock the signing service."""
    from .client import SignerClient
    config = _get_config(home)
    try:
        client = SignerClient(socket_path=config.socket_path)
        client.lock()
        click.echo("Signer locked.")
    except Exception as e:
        raise click.ClickException(str(e))


@main.command("change-password")
@click.option("--home", default=None, help="Override home directory")
def change_password(home):
    """Change the keystore encryption password."""
    config = _get_config(home)
    ks = Keystore.load(config.keystore_path)

    old_pass_str = click.prompt("Enter current password", hide_input=True)
    old_pass = bytearray(old_pass_str.encode("utf-8"))
    del old_pass_str

    try:
        keys = ks.decrypt_all(old_pass)
    except Exception as e:
        raise click.ClickException(f"Wrong password: {e}")
    finally:
        zeroize(old_pass)

    new_pass_str = click.prompt("Enter new password", hide_input=True)
    confirm_str = click.prompt("Confirm new password", hide_input=True)
    if new_pass_str != confirm_str:
        for key in keys:
            if key.private_key:
                zeroize(key.private_key)
        raise click.ClickException("Passwords do not match")
    if len(new_pass_str) < config.min_password_length:
        for key in keys:
            if key.private_key:
                zeroize(key.private_key)
        raise click.ClickException(
            f"Password must be at least {config.min_password_length} characters"
        )

    new_pass = bytearray(new_pass_str.encode("utf-8"))
    del new_pass_str, confirm_str

    new_ks = Keystore(config.keystore_path)
    try:
        for key in keys:
            new_ks.add_key(
                name=key.name,
                key_type=key.key_type,
                address=key.address,
                private_key=key.private_key,
                password=bytearray(new_pass),
            )
        new_ks.save()
    finally:
        zeroize(new_pass)
        for key in keys:
            if key.private_key:
                zeroize(key.private_key)

    click.echo("Password changed successfully.")
