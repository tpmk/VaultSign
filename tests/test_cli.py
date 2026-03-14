# tests/test_cli.py
import json
import os
import signal

import click
import pytest
from click.testing import CliRunner
from unittest.mock import patch

from crypto_signer.cli import main


@pytest.fixture
def runner():
    return CliRunner()


def test_init_creates_directory(runner, tmp_path):
    home = str(tmp_path / ".crypto-signer")
    result = runner.invoke(main, ["init", "--home", home])
    assert result.exit_code == 0
    assert (tmp_path / ".crypto-signer").exists()
    assert (tmp_path / ".crypto-signer" / "config.toml").exists()


def test_list_empty(runner, tmp_path):
    home = str(tmp_path / ".crypto-signer")
    (tmp_path / ".crypto-signer").mkdir()
    ks_path = tmp_path / ".crypto-signer" / "keystore.json"
    ks_path.write_text(json.dumps({"version": 1, "kdf": "argon2id", "kdf_params": {}, "keys": []}))

    result = runner.invoke(main, ["list", "--home", home])
    assert result.exit_code == 0
    assert "No keys" in result.output


def test_add_key_interactive(runner, tmp_path):
    home = str(tmp_path / ".crypto-signer")
    (tmp_path / ".crypto-signer").mkdir()
    ks_path = tmp_path / ".crypto-signer" / "keystore.json"
    ks_path.write_text(json.dumps({"version": 1, "kdf": "argon2id", "kdf_params": {}, "keys": []}))

    # Simulate interactive input: private key + password + confirm
    test_key = "4c0883a69102937d6231471b5dbb6204fe512961708279f15b0d7e4b2cd53f37"
    input_text = f"{test_key}\ntestpass1234\ntestpass1234\n"

    result = runner.invoke(
        main,
        ["add", "--name", "test-evm", "--type", "evm", "--key", "--home", home],
        input=input_text,
    )
    assert result.exit_code == 0, f"CLI output: {result.output}"

    # Verify keystore has the key
    data = json.loads(ks_path.read_text())
    assert len(data["keys"]) == 1
    assert data["keys"][0]["name"] == "test-evm"


def test_remove_key(runner, tmp_path):
    home = str(tmp_path / ".crypto-signer")
    (tmp_path / ".crypto-signer").mkdir()
    ks_path = tmp_path / ".crypto-signer" / "keystore.json"
    ks_path.write_text(json.dumps({"version": 1, "kdf": "argon2id", "kdf_params": {}, "keys": []}))

    # Add a key first
    test_key = "4c0883a69102937d6231471b5dbb6204fe512961708279f15b0d7e4b2cd53f37"
    runner.invoke(
        main,
        ["add", "--name", "test-evm", "--type", "evm", "--key", "--home", home],
        input=f"{test_key}\ntestpass1234\ntestpass1234\n",
    )

    # Remove it
    result = runner.invoke(main, ["remove", "--name", "test-evm", "--home", home])
    assert result.exit_code == 0

    data = json.loads(ks_path.read_text())
    assert len(data["keys"]) == 0


from crypto_signer.cli import _check_stale_pid


def test_check_stale_pid_cleans_dead_process(tmp_path):
    """Stale PID file (dead process) should be cleaned up."""
    home = str(tmp_path / ".crypto-signer")
    os.makedirs(home, exist_ok=True)
    pid_file = os.path.join(home, "signer.pid")

    # Write a PID that doesn't exist
    with open(pid_file, "w") as f:
        f.write("99999999")

    from crypto_signer.config import Config
    config = Config(home_dir=home)

    with patch("crypto_signer.cli.os.kill", side_effect=OSError("No such process")):
        _check_stale_pid(config)

    assert not os.path.exists(pid_file)


def test_check_stale_pid_aborts_if_alive(tmp_path):
    """If PID is alive, should raise ClickException."""
    home = str(tmp_path / ".crypto-signer")
    os.makedirs(home, exist_ok=True)
    pid_file = os.path.join(home, "signer.pid")

    with open(pid_file, "w") as f:
        f.write("12345")

    from crypto_signer.config import Config
    config = Config(home_dir=home)

    with patch("crypto_signer.cli.os.kill", return_value=None):  # process exists
        with pytest.raises(click.ClickException, match="already running"):
            _check_stale_pid(config)


def test_check_stale_pid_treats_permission_error_as_alive(tmp_path):
    """PermissionError means process exists but inaccessible — treat as alive."""
    home = str(tmp_path / ".crypto-signer")
    os.makedirs(home, exist_ok=True)
    pid_file = os.path.join(home, "signer.pid")

    with open(pid_file, "w") as f:
        f.write("12345")

    from crypto_signer.config import Config
    config = Config(home_dir=home)

    with patch("crypto_signer.cli.os.kill", side_effect=PermissionError("Access denied")):
        with pytest.raises(click.ClickException, match="already running"):
            _check_stale_pid(config)
