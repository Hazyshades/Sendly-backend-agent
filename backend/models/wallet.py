from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class DeveloperWallet:
    id: Optional[int] = None
    user_id: str = ''
    telegram_user_id: Optional[str] = None
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
        normalized_user_id = self.user_id.lower() if self.user_id else None
        normalized_telegram_id = (
            self.telegram_user_id.lower() if self.telegram_user_id else None
        )

        data = {
            'circle_wallet_id': self.circle_wallet_id,
            'circle_wallet_set_id': self.circle_wallet_set_id,
            'wallet_address': self.wallet_address,
            'blockchain': self.blockchain,
            'account_type': self.account_type,
            'state': self.state,
            'custody_type': self.custody_type
        }

        if normalized_user_id is not None:
            data['user_id'] = normalized_user_id

        if normalized_telegram_id is not None:
            data['telegram_user_id'] = normalized_telegram_id

        return data
    
    @staticmethod
    def from_dict(data: dict) -> 'DeveloperWallet':
        return DeveloperWallet(
            id=data.get('id'),
            user_id=data.get('user_id', ''),
            telegram_user_id=data.get('telegram_user_id'),
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

