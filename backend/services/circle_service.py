from typing import Optional, Dict, Any, List
from uuid import uuid4
import logging

from circle.web3 import utils
from circle.web3.developer_controlled_wallets.api.wallets_api import WalletsApi
from circle.web3.developer_controlled_wallets.api.transactions_api import TransactionsApi
from circle.web3.developer_controlled_wallets.api.signing_api import SigningApi
from circle.web3.developer_controlled_wallets.models import (
    CreateWalletRequest,
    CreateTransferTransactionForDeveloperRequest,
    SignMessageRequest,
)
from circle.web3.developer_controlled_wallets.models.blockchain import Blockchain
from circle.web3.developer_controlled_wallets.models.transfer_blockchain import TransferBlockchain
from circle.web3.developer_controlled_wallets.models.token_standard import TokenStandard
from circle.web3.developer_controlled_wallets.models.fee_level import FeeLevel
from circle.web3.configurations.api.faucet_api import FaucetApi
from circle.web3.configurations.models.faucet_request import FaucetRequest
from circle.web3.configurations.models.testnet_blockchain import TestnetBlockchain

logger = logging.getLogger(__name__)


class CircleService:

    def __init__(self, api_key: str, entity_secret: str):
        self.api_key = api_key
        self.entity_secret = entity_secret
        self.client: Optional[Any] = None
        self.config_client: Optional[Any] = None
        self.wallets_api: Optional[WalletsApi] = None
        self.transactions_api: Optional[TransactionsApi] = None
        self.signing_api: Optional[SigningApi] = None
        self.faucet_api: Optional[FaucetApi] = None
        self._initialize_client()

    def _initialize_client(self):
        try:
            self.client = utils.init_developer_controlled_wallets_client(
                api_key=self.api_key,
                entity_secret=self.entity_secret
            )
            self.config_client = utils.init_configurations_client(api_key=self.api_key)

            self.wallets_api = WalletsApi(self.client)
            self.transactions_api = TransactionsApi(self.client)
            self.signing_api = SigningApi(self.client)
            self.faucet_api = FaucetApi(self.config_client)

            logger.info("✅ Circle SDK client initialized successfully")
        except ImportError as e:
            logger.warning(
                "⚠️ Circle SDK is not installed: %s. Install the circle-developer-controlled-wallets package",
                e
            )
        except Exception as e:
            logger.error("❌ Circle SDK initialization error: %s", e)

    @staticmethod
    def _as_blockchain(value: str) -> Optional[Blockchain]:
        try:
            return Blockchain(value)
        except ValueError:
            logger.error("Unknown blockchain for wallet: %s", value)
            return None

    @staticmethod
    def _as_transfer_blockchain(value: str) -> Optional[TransferBlockchain]:
        try:
            return TransferBlockchain(value)
        except ValueError:
            logger.error("Unknown blockchain for transaction: %s", value)
            return None

    @staticmethod
    def _as_testnet_blockchain(value: str) -> Optional[TestnetBlockchain]:
        try:
            return TestnetBlockchain(value)
        except ValueError:
            logger.error("Unknown testnet blockchain: %s", value)
            return None

    async def derive_wallet(
        self,
        wallet_set_id: str,
        blockchain: str,
        metadata: Optional[Dict[str, str]] = None
    ) -> Optional[Dict[str, Any]]:
        # if not self.wallets_api:
        #     logger.error("Circle API is not initialized")
        #     return None
        #
        # blockchain_enum = self._as_blockchain(blockchain)
        # if not blockchain_enum:
        #     return None
        #
        # try:
        #     logger.info("Creating EOA wallet for blockchain: %s", blockchain)
        #
        #     request_payload = {
        #         "walletSetId": wallet_set_id,
        #         "accountType": "EOA",
        #         "blockchains": [blockchain_enum.value],
        #         "count": 1,
        #         "idempotencyKey": str(uuid4()),
        #     }
        #
        #     if metadata:
        #         request_payload["metadata"] = [metadata]
        #
        #     request = CreateWalletRequest.from_dict(request_payload)
        #     response = self.wallets_api.create_wallet(request)
        #
        #     if response.data.wallets:
        #         wallet_info = response.data.wallets[0].actual_instance
        #         logger.info("✅ EOA wallet created: %s", wallet_info.address)
        #         blockchain_value = getattr(wallet_info.blockchain, "value", wallet_info.blockchain)
        #         state_value = getattr(wallet_info.state, "value", wallet_info.state)
        #         return {
        #             "id": wallet_info.id,
        #             "address": wallet_info.address,
        #             "blockchain": blockchain_value,
        #             "state": state_value,
        #             "walletSetId": wallet_info.wallet_set_id,
        #         }
        #
        #     return None
        # except Exception as e:
        #     logger.error("❌ Wallet creation error: %s", e)
        #     return None
        return None

    async def create_transaction(
        self,
        wallet_id: str,
        destination_address: str,
        amount: List[str],
        token_id: Optional[str] = None,
        token_address: Optional[str] = None,
        blockchain: Optional[str] = None,
        fee_level: str = "MEDIUM",
        ref_id: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        if not self.transactions_api:
            logger.error("Circle API is not initialized")
            return None

        transfer_blockchain = self._as_transfer_blockchain(blockchain) if blockchain else None

        try:
            logger.info("Creating transaction: %s -> %s", amount, destination_address)

            normalized_fee_level = (fee_level or "").upper()
            fee_level_value = (
                FeeLevel[normalized_fee_level].value
                if normalized_fee_level in FeeLevel.__members__
                else FeeLevel.MEDIUM.value
            )

            request_payload: Dict[str, Any] = {
                "walletId": wallet_id,
                "destinationAddress": destination_address,
                "amounts": amount,
                "idempotencyKey": str(uuid4()),
                "feeLevel": fee_level_value,
            }

            if transfer_blockchain:
                request_payload["blockchain"] = transfer_blockchain.value

            if token_id:
                request_payload["tokenId"] = token_id
            elif token_address:
                request_payload["tokenAddress"] = token_address

            if ref_id:
                request_payload["refId"] = ref_id

            request = CreateTransferTransactionForDeveloperRequest.from_dict(request_payload)
            response = self.transactions_api.create_developer_transaction_transfer(request)

            if response.data:
                logger.info("✅ Transaction created: %s", response.data.id)
                state_value = getattr(response.data.state, "value", response.data.state)
                return {
                    "id": response.data.id,
                    "state": state_value,
                    "txHash": None,
                }

            return None
        except Exception as e:
            logger.error("❌ Transaction creation error: %s", e)
            return None

    async def get_wallet_balance(
        self,
        wallet_id: str,
        standard: Optional[str] = "ERC20"
    ) -> Optional[List[Dict[str, Any]]]:
        if not self.wallets_api:
            logger.error("Circle API is not initialized")
            return None

        standard_enum = None
        if standard:
            try:
                standard_enum = TokenStandard(standard)
            except ValueError:
                logger.warning("Unknown token standard: %s", standard)

        try:
            logger.info("Fetching wallet balance: %s", wallet_id)

            balance_response = self.wallets_api.list_wallet_balance(
                wallet_id,
                standard=standard_enum,
            )

            balances = []
            token_balances = balance_response.data.token_balances if balance_response.data else []
            if token_balances:
                for balance in token_balances:
                    token_info = balance.token.to_dict() if balance.token else {}
                    update_date = (
                        balance.update_date.isoformat()
                        if hasattr(balance.update_date, "isoformat")
                        else str(balance.update_date)
                    )
                    balances.append(
                        {
                            "token": token_info,
                            "amount": balance.amount,
                            "updateDate": update_date,
                        }
                    )
                logger.info("✅ Retrieved balance entries: %d", len(balances))

            return balances
        except Exception as e:
            logger.error("❌ Wallet balance retrieval error: %s", e)
            return None

    async def sign_message(
        self,
        wallet_id: str,
        message: str,
        encoded_by_hex: bool = False,
        memo: Optional[str] = None
    ) -> Optional[str]:
        if not self.signing_api:
            logger.error("Circle API is not initialized")
            return None

        try:
            request_payload = {
                "walletId": wallet_id,
                "message": message,
                "encodedByHex": encoded_by_hex,
            }

            if memo:
                request_payload["memo"] = memo

            request = SignMessageRequest.from_dict(request_payload)
            response = self.signing_api.sign_message(request)

            if response.data:
                logger.info("✅ Message signed successfully")
                return response.data.signature

            return None
        except Exception as e:
            logger.error("❌ Message signing error: %s", e)
            return None

    async def request_testnet_tokens(
        self,
        address: str,
        blockchain: str,
        usdc: bool = False,
        eurc: bool = False,
        native: bool = False
    ) -> bool:
        if not self.faucet_api:
            logger.error("Circle API is not initialized")
            return False

        blockchain_enum = self._as_testnet_blockchain(blockchain)
        if not blockchain_enum:
            return False

        try:
            request = FaucetRequest(
                address=address,
                blockchain=blockchain_enum,
                usdc=usdc,
                eurc=eurc,
                native=native,
            )

            self.faucet_api.request_testnet_tokens(faucet_request=request)
            logger.info("✅ Testnet tokens requested successfully")
            return True
        except Exception as e:
            logger.error("❌ Testnet token request error: %s", e)
            return False
