# tests/test_cli.py
import json

import pytest
from click.testing import CliRunner

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
