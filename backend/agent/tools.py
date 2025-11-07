from typing import Dict, Any, Optional, List
from services.circle_service import CircleService
from services.supabase_service import SupabaseService
# from models.wallet import DeveloperWallet
from config.settings import settings
import logging

logger = logging.getLogger(__name__)

circle_service = CircleService(
    api_key=settings.CIRCLE_API_KEY,
    entity_secret=settings.CIRCLE_ENTITY_SECRET
)

supabase_service = SupabaseService(
    url=settings.SUPABASE_URL,
    service_role_key=settings.SUPABASE_SERVICE_ROLE_KEY
)


async def get_or_create_wallet(user_id: str, blockchain: str = None) -> Dict[str, Any]:
    """
    Retrieve the user's existing wallet or create a new EOA wallet.

    Args:
        user_id: The Telegram user identifier
        blockchain: Blockchain name (for example, ARC-TESTNET)

    Returns:
        Wallet information
    """
    try:
        if blockchain is None:
            blockchain = settings.DEFAULT_BLOCKCHAIN
        
        existing_wallet = await supabase_service.get_wallet_by_user(
            user_id=user_id,
            blockchain=blockchain,
            account_type='EOA'
        )
        
        if existing_wallet:
            logger.info(f"Found existing wallet: {existing_wallet.wallet_address}")
            return {
                'wallet_id': existing_wallet.circle_wallet_id,
                'address': existing_wallet.wallet_address,
                'blockchain': existing_wallet.blockchain,
                'exists': True
            }
        
        if not settings.CIRCLE_WALLET_SET_ID:
            return {
                'error': 'CIRCLE_WALLET_SET_ID is not configured',
                'exists': False
            }
        
        # wallet_data = await circle_service.derive_wallet(
        #     wallet_set_id=settings.CIRCLE_WALLET_SET_ID,
        #     blockchain=blockchain,
        #     metadata={
        #         'name': f'EOA Wallet for {user_id}',
        #         'refId': user_id
        #     }
        # )
        #
        # if not wallet_data:
        #     return {
        #         'error': 'Failed to create wallet',
        #         'exists': False
        #     }
        #
        # new_wallet = DeveloperWallet(
        #     user_id=user_id,
        #     circle_wallet_id=wallet_data['id'],
        #     circle_wallet_set_id=wallet_data.get('walletSetId'),
        #     wallet_address=wallet_data['address'],
        #     blockchain=wallet_data['blockchain'],
        #     account_type='EOA',
        #     state=wallet_data['state'],
        #     custody_type='DEVELOPER'
        # )
        #
        # saved = await supabase_service.save_wallet(new_wallet)
        #
        # if saved:
        #     logger.info(f"Created new wallet: {new_wallet.wallet_address}")
        #     return {
        #         'wallet_id': new_wallet.circle_wallet_id,
        #         'address': new_wallet.wallet_address,
        #         'blockchain': new_wallet.blockchain,
        #         'exists': False
        #     }
        #
        # return {
        #     'error': 'Failed to save wallet to the database',
        #     'exists': False
        # }
        return {
            'error': 'Wallet creation is currently disabled',
            'exists': False
        }
    
    except Exception as e:
        logger.error(f"Error in get_or_create_wallet: {e}")
        return {
            'error': str(e),
            'exists': False
        }


async def check_wallet_balance(wallet_id: str) -> Dict[str, Any]:
    """
    Retrieve wallet balances.

    Args:
        wallet_id: Circle wallet ID

    Returns:
        List of token balances
    """
    try:
        balances = await circle_service.get_wallet_balance(
            wallet_id=wallet_id,
            standard='ERC20'
        )
        
        if balances is None:
            return {'error': 'Failed to fetch balance'}
        
        return {'balances': balances}
    
    except Exception as e:
        logger.error(f"Error in check_wallet_balance: {e}")
        return {'error': str(e)}


async def send_transaction(
    wallet_id: str,
    destination_address: str,
    amount: List[str],
    token_id: Optional[str] = None,
    token_address: Optional[str] = None,
    blockchain: Optional[str] = None,
    fee_level: str = 'MEDIUM'
) -> Dict[str, Any]:
    """
    Submit a transaction.

    Args:
        wallet_id: Circle wallet ID
        destination_address: Recipient address
        amount: Amount as a list of strings
        token_id: Token ID (optional)
        token_address: Token address (optional)
        blockchain: Blockchain name (optional)
        fee_level: Fee level (LOW, MEDIUM, HIGH)

    Returns:
        Transaction details
    """
    try:
        tx_data = await circle_service.create_transaction(
            wallet_id=wallet_id,
            destination_address=destination_address,
            amount=amount,
            token_id=token_id,
            token_address=token_address,
            blockchain=blockchain,
            fee_level=fee_level
        )
        
        if not tx_data:
            return {'error': 'Failed to create transaction'}
        
        return {
            'transaction_id': tx_data['id'],
            'state': tx_data['state'],
            'tx_hash': tx_data.get('txHash')
        }
    
    except Exception as e:
        logger.error(f"Error in send_transaction: {e}")
        return {'error': str(e)}


async def sign_wallet_message(
    wallet_id: str,
    message: str,
    encoded_by_hex: bool = False,
    memo: Optional[str] = None
) -> Dict[str, Any]:
    """
    Sign a message with the wallet.

    Args:
        wallet_id: Circle wallet ID
        message: Message to sign
        encoded_by_hex: Indicates whether the message is hex encoded
        memo: Operation description

    Returns:
        Message signature
    """
    try:
        signature = await circle_service.sign_message(
            wallet_id=wallet_id,
            message=message,
            encoded_by_hex=encoded_by_hex,
            memo=memo
        )
        
        if not signature:
            return {'error': 'Failed to sign message'}
        
        return {'signature': signature}
    
    except Exception as e:
        logger.error(f"Error in sign_wallet_message: {e}")
        return {'error': str(e)}


async def request_testnet_tokens_for_wallet(
    address: str,
    blockchain: str,
    usdc: bool = True,
    eurc: bool = False,
    native: bool = True
) -> Dict[str, Any]:
    """
    Request testnet tokens for the wallet.

    Args:
        address: Wallet address
        blockchain: Testnet blockchain name
        usdc: Request USDC
        eurc: Request EURC
        native: Request native tokens

    Returns:
        Request result
    """
    try:
        success = await circle_service.request_testnet_tokens(
            address=address,
            blockchain=blockchain,
            usdc=usdc,
            eurc=eurc,
            native=native
        )
        
        if success:
            return {'success': True, 'message': 'Testnet tokens requested'}

        return {'success': False, 'error': 'Failed to request testnet tokens'}
    
    except Exception as e:
        logger.error(f"Error in request_testnet_tokens_for_wallet: {e}")
        return {'success': False, 'error': str(e)}