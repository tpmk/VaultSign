"""web3.py middleware for automatic transaction signing via crypto-signer."""

from ..client import SignerClient


class SignerMiddleware:
    """web3.py middleware that signs transactions using the crypto-signer daemon.

    Usage:
        from web3 import Web3
        from crypto_signer.web3 import SignerMiddleware

        w3 = Web3(Web3.HTTPProvider("https://..."))
        w3.middleware_onion.add(SignerMiddleware())
    """

    def __init__(self, client: SignerClient | None = None, socket_path: str | None = None):
        if client:
            self._client = client
        else:
            self._client = SignerClient(socket_path=socket_path)

    def __call__(self, make_request, w3):
        def middleware(method, params):
            if method == "eth_sendTransaction":
                tx = params[0]
                if "from" not in tx:
                    tx["from"] = self._client.evm.get_address()

                result = self._client.evm.sign_transaction(tx)
                return make_request("eth_sendRawTransaction", [result["signed_tx"]])

            return make_request(method, params)

        return middleware
