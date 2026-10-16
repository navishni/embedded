"""Web3.py bridge to the IncidentLedger smart contract."""
import json
import logging
import threading

log = logging.getLogger(__name__)


class BlockchainUnavailable(Exception):
    pass


class Ledger:
    def __init__(self, rpc_url, contract_info_path, private_key=""):
        self.rpc_url = rpc_url
        self.contract_info_path = contract_info_path
        self.private_key = private_key
        self._w3 = None
        self._contract = None
        self._account = None
        self._lock = threading.Lock()  # serialise txs so nonces don't collide

    def _connect(self):
        if self._contract is not None and self._w3.is_connected():
            return
        from web3 import Web3

        if not self.contract_info_path.exists():
            raise BlockchainUnavailable(
                f"{self.contract_info_path} not found - deploy the contract first")
        info = json.loads(self.contract_info_path.read_text())
        w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={"timeout": 5}))
        if not w3.is_connected():
            raise BlockchainUnavailable(f"cannot reach node at {self.rpc_url}")
        if self.private_key:
            self._account = w3.eth.account.from_key(self.private_key)
        else:
            # Hardhat's local node exposes unlocked dev accounts.
            self._account = None
            w3.eth.default_account = w3.eth.accounts[0]
        self._w3 = w3
        self._contract = w3.eth.contract(address=info["address"], abi=info["abi"])

    @property
    def sender(self):
        return self._account.address if self._account else self._w3.eth.default_account

    def record(self, incident_id, timestamp, camera_id, evidence_hash_hex):
        """Write an incident to the chain. Returns the transaction hash."""
        with self._lock:
            try:
                self._connect()
                fn = self._contract.functions.recordIncident(
                    incident_id, int(timestamp), camera_id, bytes.fromhex(evidence_hash_hex))
                if self._account:
                    tx = fn.build_transaction({
                        "from": self._account.address,
                        "nonce": self._w3.eth.get_transaction_count(self._account.address, "pending"),
                    })
                    signed = self._account.sign_transaction(tx)
                    tx_hash = self._w3.eth.send_raw_transaction(signed.raw_transaction)
                else:
                    tx_hash = fn.transact()
                receipt = self._w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
                if receipt.status != 1:
                    raise BlockchainUnavailable("transaction reverted")
                tx_hex = tx_hash.hex()
                return tx_hex if tx_hex.startswith("0x") else "0x" + tx_hex
            except BlockchainUnavailable:
                raise
            except Exception as e:
                self._contract = None  # force reconnect next time
                raise BlockchainUnavailable(str(e)) from e

    def fetch(self, incident_id):
        """Return the on-chain record or None if it was never recorded."""
        with self._lock:
            try:
                self._connect()
                exists, ts, cam, h, recorder, block_time = \
                    self._contract.functions.getIncident(incident_id).call()
            except BlockchainUnavailable:
                raise
            except Exception as e:
                self._contract = None
                raise BlockchainUnavailable(str(e)) from e
        if not exists:
            return None
        return {"timestamp": ts, "camera_id": cam, "evidence_hash": h.hex(),
                "recorder": recorder, "block_time": block_time}
