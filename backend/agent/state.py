from typing import TypedDict, Optional, List, Dict, Any


class AgentState(TypedDict, total=False):
    user_id: str
    message_type: str
    raw_input: Optional[str]
    voice_file_path: Optional[str]
    
    parsed_command: Optional[Dict[str, Any]]
    
    wallet_id: Optional[str]
    wallet_address: Optional[str]
    blockchain: str
    
    operation: Optional[str]
    
    balance: Optional[List[Dict[str, Any]]]
    
    transaction_id: Optional[str]
    transaction_state: Optional[str]
    transaction_hash: Optional[str]
    
    destination_address: Optional[str]
    amount: Optional[List[str]]
    token_id: Optional[str]
    token_address: Optional[str]
    fee_level: str
    
    message: Optional[str]
    signature: Optional[str]
    
    testnet_tokens_requested: bool
    
    error: Optional[str]
    response: str

