import pytest

from vaultsign.web3.middleware import SignerMiddleware


def test_middleware_instantiates():
    """Basic smoke test — middleware can be created with a mock client."""

    class MockEVM:
        def sign_transaction(self, tx):
            return {"signed_tx": "0xabc123", "tx_hash": "0xdef456"}

        def get_address(self):
            return "0x1234567890abcdef1234567890abcdef12345678"

    class MockClient:
        evm = MockEVM()

    mw = SignerMiddleware(client=MockClient())
    assert mw is not None
    assert mw._client.evm.get_address() == "0x1234567890abcdef1234567890abcdef12345678"
