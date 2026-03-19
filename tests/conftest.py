import pytest


@pytest.fixture
def tmp_home(tmp_path):
    """Provide a temporary home directory for tests."""
    home = tmp_path / ".vaultsign"
    home.mkdir()
    return home


@pytest.fixture
def keystore_path(tmp_home):
    """Path to a temporary keystore.json."""
    return tmp_home / "keystore.json"
