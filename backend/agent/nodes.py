from typing import Dict, Any
from langchain_core.messages import HumanMessage, SystemMessage
from langchain.chat_models import ChatOpenAI
from agent.state import AgentState
from agent.tools import (
    get_or_create_wallet,
    check_wallet_balance,
    send_transaction,
    sign_wallet_message,
    request_testnet_tokens_for_wallet
)
from config.settings import settings
import logging
import json

logger = logging.getLogger(__name__)


llm = ChatOpenAI(
    model="gpt-4.1-nano-2025-04-14", # TODO: change to gpt-4
    api_key=settings.AIMLAPI_API_KEY,
    base_url="https://api.aimlapi.com/v1"
)


async def parse_command_node(state: AgentState) -> Dict[str, Any]:
    """
    Parse the user command and determine the intent.
    """
    logger.info("Node: parse_command")
    
    raw_input = state.get('raw_input', '')
    
    if not raw_input:
        return {
            'error': 'No input text provided',
            'response': 'Please send a command to process.'
        }
    
    system_prompt = """
    You are an assistant for working with crypto wallets using the Circle SDK.

    Determine the user's intent from their message and extract the parameters.

    Possible operations:
    - get_wallet: retrieve or create a wallet
    - check_balance: check a balance
    - send_transaction: send a transaction
    - sign_message: sign a message
    - request_testnet_tokens: request testnet tokens

    Return JSON with the fields:
    {
        "operation": "operation_name",
        "blockchain": "ARC-TESTNET",
        "destination_address": "recipient address (if any)",
        "amount": ["amount (if any)"],
        "token_type": "USDC or EURC (if any)",
        "message": "message to sign (if any)",
        "usdc": true/false,
        "eurc": true/false,
        "native": true/false
    }
    """
    
    try:
        messages = [
            SystemMessage(content=system_prompt),
            HumanMessage(content=f"User command: {raw_input}")
        ]
        
        response = await llm.ainvoke(messages)
        
        content = response.content
        
        if isinstance(content, str):
            content_stripped = content.strip()
            if content_stripped.startswith('```json'):
                content_stripped = content_stripped[7:]
            if content_stripped.endswith('```'):
                content_stripped = content_stripped[:-3]
            content_stripped = content_stripped.strip()
            
            parsed = json.loads(content_stripped)
        else:
            parsed = content
        
        logger.info(f"Recognized operation: {parsed.get('operation')}")
        
        return {
            'parsed_command': parsed,
            'operation': parsed.get('operation'),
            'blockchain': parsed.get('blockchain', settings.DEFAULT_BLOCKCHAIN),
            'destination_address': parsed.get('destination_address'),
            'amount': parsed.get('amount'),
            'token_address': settings.USDC_ADDRESS if parsed.get('token_type') == 'USDC' else settings.EURC_ADDRESS,
            'message': parsed.get('message'),
            'testnet_tokens_requested': False
        }
    
    except Exception as e:
        logger.error(f"Error parsing command: {e}")
        return {
            'error': f'Failed to interpret the command: {str(e)}',
            'response': 'Sorry, I did not understand your command. Please try phrasing it differently.'
        }


async def get_wallet_node(state: AgentState) -> Dict[str, Any]:
    """
    Retrieve or create a wallet for the user.
    """
    logger.info("Node: get_wallet")
    
    user_id = state.get('user_id')
    blockchain = state.get('blockchain', settings.DEFAULT_BLOCKCHAIN)
    
    if not user_id:
        return {
            'error': 'user_id not provided',
            'response': 'Unable to identify the user.'
        }
    
    result = await get_or_create_wallet(user_id=user_id, blockchain=blockchain)
    
    if 'error' in result:
        return {
            'error': result['error'],
            'response': f"Error retrieving wallet: {result['error']}"
        }
    
    return {
        'wallet_id': result['wallet_id'],
        'wallet_address': result['address'],
        'blockchain': result['blockchain'],
        'response': f"Wallet: {result['address']}" +
                   (" (newly created)" if not result['exists'] else " (existing)")
    }


async def check_balance_node(state: AgentState) -> Dict[str, Any]:
    """
    Check the wallet balance.
    """
    logger.info("Node: check_balance")
    
    wallet_id = state.get('wallet_id')
    
    if not wallet_id:
        return {
            'error': 'wallet_id not provided',
            'response': 'Wallet not found.'
        }
    
    result = await check_wallet_balance(wallet_id=wallet_id)
    
    if 'error' in result:
        return {
            'error': result['error'],
            'response': f"Error while checking balance: {result['error']}"
        }
    
    balances = result.get('balances', [])
    
    if not balances:
        return {
            'balance': [],
            'response': 'Wallet balance: 0 (no tokens found)'
        }
    
    balance_text = "Wallet balance:\n"
    for b in balances:
        token_name = b.get('token', {}).get('name', 'Unknown token')
        amount = b.get('amount', '0')
        balance_text += f"- {token_name}: {amount}\n"
    
    return {
        'balance': balances,
        'response': balance_text.strip()
    }


async def send_transaction_node(state: AgentState) -> Dict[str, Any]:
    """
    Send a transaction.
    """
    logger.info("Node: send_transaction")
    
    wallet_id = state.get('wallet_id')
    destination = state.get('destination_address')
    amount = state.get('amount')
    token_address = state.get('token_address')
    blockchain = state.get('blockchain')
    fee_level = state.get('fee_level', 'MEDIUM')
    
    if not wallet_id:
        return {'error': 'wallet_id not provided', 'response': 'Wallet not found.'}
    
    if not destination:
        return {'error': 'destination_address not provided', 'response': 'Destination address is missing.'}
    
    if not amount:
        return {'error': 'amount not provided', 'response': 'Amount is missing.'}
    
    result = await send_transaction(
        wallet_id=wallet_id,
        destination_address=destination,
        amount=amount,
        token_address=token_address,
        blockchain=blockchain,
        fee_level=fee_level
    )
    
    if 'error' in result:
        return {
            'error': result['error'],
            'response': f"Error while submitting transaction: {result['error']}"
        }
    
    return {
        'transaction_id': result['transaction_id'],
        'transaction_state': result['state'],
        'transaction_hash': result.get('tx_hash'),
        'response': f"Transaction created!\nID: {result['transaction_id']}\nStatus: {result['state']}"
    }


async def sign_message_node(state: AgentState) -> Dict[str, Any]:
    """
    Sign a message.
    """
    logger.info("Node: sign_message")
    
    wallet_id = state.get('wallet_id')
    message = state.get('message')
    
    if not wallet_id:
        return {'error': 'wallet_id not provided', 'response': 'Wallet not found.'}
    
    if not message:
        return {'error': 'message not provided', 'response': 'No message provided for signing.'}
    
    result = await sign_wallet_message(
        wallet_id=wallet_id,
        message=message,
        encoded_by_hex=False
    )
    
    if 'error' in result:
        return {
            'error': result['error'],
            'response': f"Error while signing the message: {result['error']}"
        }
    
    return {
        'signature': result['signature'],
        'response': f"Message signed!\nSignature: {result['signature']}"
    }


async def request_testnet_tokens_node(state: AgentState) -> Dict[str, Any]:
    """
    Request testnet tokens.
    """
    logger.info("Node: request_testnet_tokens")
    
    wallet_address = state.get('wallet_address')
    blockchain = state.get('blockchain', settings.DEFAULT_BLOCKCHAIN)
    parsed_command = state.get('parsed_command', {})
    
    usdc = parsed_command.get('usdc', True)
    eurc = parsed_command.get('eurc', False)
    native = parsed_command.get('native', True)
    
    if not wallet_address:
        return {'error': 'wallet_address not provided', 'response': 'Wallet address not found.'}
    
    result = await request_testnet_tokens_for_wallet(
        address=wallet_address,
        blockchain=blockchain,
        usdc=usdc,
        eurc=eurc,
        native=native
    )
    
    if not result.get('success'):
        return {
            'error': result.get('error'),
            'response': f"Error requesting testnet tokens: {result.get('error')}"
        }
    
    tokens = []
    if usdc:
        tokens.append('USDC')
    if eurc:
        tokens.append('EURC')
    if native:
        tokens.append('native tokens')
    
    tokens_text = ', '.join(tokens)
    
    return {
        'testnet_tokens_requested': True,
        'response': f"Testnet tokens requested: {tokens_text}\nThey will arrive at {wallet_address} within a few minutes."
    }

