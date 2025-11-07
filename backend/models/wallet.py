from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class DeveloperWallet:
    id: Optional[int] = None
    user_id: str = ''
    circle_wallet_id: str = ''
    circle_wallet_set_id: Optional[str] = None
    wallet_address: str = ''
    blockchain: str = ''
    account_type: str = 'EOA'
    state: str = 'LIVE'
    custody_type: str = 'DEVELOPER'
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def to_dict(self) -> dict:
        return {
            'telegram_user_id': self.user_id.lower(),
            'circle_wallet_id': self.circle_wallet_id,
            'circle_wallet_set_id': self.circle_wallet_set_id,
            'wallet_address': self.wallet_address,
            'blockchain': self.blockchain,
            'account_type': self.account_type,
            'state': self.state,
            'custody_type': self.custody_type
        }
    
    @staticmethod
    def from_dict(data: dict) -> 'DeveloperWallet':
        return DeveloperWallet(
            id=data.get('id'),
            user_id=data.get('telegram_user_id', ''),
            circle_wallet_id=data.get('circle_wallet_id', ''),
            circle_wallet_set_id=data.get('circle_wallet_set_id'),
            wallet_address=data.get('wallet_address', ''),
            blockchain=data.get('blockchain', ''),
            account_type=data.get('account_type', 'EOA'),
            state=data.get('state', 'LIVE'),
            custody_type=data.get('custody_type', 'DEVELOPER'),
            created_at=data.get('created_at'),
            updated_at=data.get('updated_at')
        )

