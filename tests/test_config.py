from crypto_signer.config import Config


def test_default_config():
    c = Config()
    assert c.socket_path.endswith("signer.sock")
    assert c.unlock_timeout == 0
    assert c.disable_core_dump is True
    assert c.try_mlock is True
    assert c.max_request_size == 1048576
    assert c.rate_limit == 60
    assert c.min_password_length == 8
    assert c.max_unlock_attempts == 5


def test_config_from_toml(tmp_path):
    toml_file = tmp_path / "config.toml"
    toml_file.write_text(
        '[signer]\n'
        'unlock_timeout = 3600\n'
        'try_mlock = false\n'
        '\n'
        '[security]\n'
        'rate_limit = 120\n'
    )
    c = Config.from_file(str(toml_file))
    assert c.unlock_timeout == 3600
    assert c.try_mlock is False
    assert c.rate_limit == 120
    assert c.max_request_size == 1048576


def test_config_home_dir():
    c = Config()
    assert c.home_dir.endswith(".crypto-signer")


def test_config_missing_file_uses_defaults():
    c = Config.from_file("/nonexistent/path/config.toml")
    assert c.unlock_timeout == 0
