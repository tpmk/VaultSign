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


def test_from_file_sets_home_dir_to_config_parent(tmp_path):
    """from_file() should derive home_dir from the config file's directory."""
    config_dir = tmp_path / "custom-home"
    config_dir.mkdir()
    toml_file = config_dir / "config.toml"
    toml_file.write_text(
        '[signer]\n'
        'unlock_timeout = 300\n'
    )
    c = Config.from_file(str(toml_file))
    assert c.home_dir == str(config_dir)
    assert c.keystore_path == str(config_dir / "keystore.json")
    assert c.socket_path == str(config_dir / "signer.sock")
    assert c.pid_path == str(config_dir / "signer.pid")


def test_from_file_explicit_socket_path_not_overridden(tmp_path):
    """If socket_path is set in the TOML, it should not be overridden."""
    config_dir = tmp_path / "custom-home"
    config_dir.mkdir()
    toml_file = config_dir / "config.toml"
    toml_file.write_text(
        '[signer]\n'
        'socket_path = "/custom/signer.sock"\n'
    )
    c = Config.from_file(str(toml_file))
    assert c.home_dir == str(config_dir)
    assert c.socket_path == "/custom/signer.sock"


def test_load_home_dir_overrides_from_file(tmp_path):
    """Config.load(home_dir=...) should override from_file's home_dir."""
    override_dir = tmp_path / "override-home"
    override_dir.mkdir()
    (override_dir / "config.toml").write_text('[signer]\n')

    c = Config.load(home_dir=str(override_dir))
    assert c.home_dir == str(override_dir)
