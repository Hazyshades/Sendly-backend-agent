from dataclasses import dataclass
from typing import Optional, List


@dataclass
class Transaction:
    id: Optional[str] = None
    wallet_id: str = ''
    destination_address: str = ''
    amount: List[str] = None
    token_id: Optional[str] = None
    token_address: Optional[str] = None
    blockchain: Optional[str] = None
    state: str = 'INITIATED'
    ref_id: Optional[str] = None
    fee_level: str = 'MEDIUM'
    
    def __post_init__(self):
        if self.amount is None:
            self.amount = []
    
    def to_dict(self) -> dict:
        result = {
            'walletId': self.wallet_id,
            'destinationAddress': self.destination_address,
            'amount': self.amount,
            'fee': {
                'type': 'level',
                'config': {
                    'feeLevel': self.fee_level
                }
            }
        }
        
        if self.token_id:
            result['tokenId'] = self.token_id
        elif self.token_address and self.blockchain:
            result['tokenAddress'] = self.token_address
            result['blockchain'] = self.blockchain
        
        if self.ref_id:
            result['refId'] = self.ref_id
        
        return result

