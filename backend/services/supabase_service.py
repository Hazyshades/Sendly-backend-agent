from typing import Optional, List, Dict, Any
from supabase import create_client, Client
import logging
from models.wallet import DeveloperWallet

logger = logging.getLogger(__name__)


class SupabaseService:
    
    def __init__(self, url: str, service_role_key: str):
        self.url = url
        self.service_role_key = service_role_key
        self.client: Optional[Client] = None
        self._initialize_client()
    
    def _initialize_client(self):
        try:
            self.client = create_client(self.url, self.service_role_key)
            logger.info("Supabase client initialized successfully")
        except Exception as e:
            logger.error(f"Supabase initialization error: {e}")
    
    async def get_wallet_by_user(
        self, 
        user_id: str, 
        blockchain: Optional[str] = None,
        account_type: str = 'EOA'
    ) -> Optional[DeveloperWallet]:
        if not self.client:
            logger.error("Supabase client is not initialized")
            return None
        
        try:
            user_id_lower = user_id.lower()
            
            query = self.client.table('developer_wallets') \
                .select('*') \
                .eq('telegram_user_id', user_id_lower) \
                .eq('account_type', account_type)
            
            if blockchain:
                query = query.eq('blockchain', blockchain)
            
            response = query.single().execute()
            
            if response.data:
                logger.info(f"Wallet found for user: {user_id}")
                return DeveloperWallet.from_dict(response.data)
            
            return None
        except Exception as e:
            logger.warning(f"Wallet not found for user {user_id}: {e}")
            return None
    
    async def get_all_wallets_by_user(
        self,
        user_id: str,
        account_type: str = 'EOA'
    ) -> List[DeveloperWallet]:
        if not self.client:
            logger.error("Supabase client is not initialized")
            return []
        
        try:
            user_id_lower = user_id.lower()
            
            response = self.client.table('developer_wallets') \
                .select('*') \
                .eq('telegram_user_id', user_id_lower) \
                .eq('account_type', account_type) \
                .execute()
            
            if response.data:
                wallets = [DeveloperWallet.from_dict(w) for w in response.data]
                logger.info(f"Wallets found: {len(wallets)} for user {user_id}")
                return wallets
            
            return []
        except Exception as e:
            logger.error(f"Error fetching wallets: {e}")
            return []
    
    async def save_wallet(self, wallet: DeveloperWallet) -> bool:
        if not self.client:
            logger.error("Supabase client is not initialized")
            return False
        
        try:
            wallet_data = wallet.to_dict()
            
            response = self.client.table('developer_wallets') \
                .insert(wallet_data) \
                .execute()
            
            if response.data:
                logger.info(f"Wallet saved: {wallet.wallet_address}")
                return True
            
            return False
        except Exception as e:
            logger.error(f"Wallet save error: {e}")
            return False
    
    async def update_wallet_state(
        self,
        circle_wallet_id: str,
        state: str
    ) -> bool:
        if not self.client:
            logger.error("Supabase client is not initialized")
            return False
        
        try:
            response = self.client.table('developer_wallets') \
                .update({'state': state}) \
                .eq('circle_wallet_id', circle_wallet_id) \
                .execute()
            
            if response.data:
                logger.info(f"Wallet state updated: {state}")
                return True
            
            return False
        except Exception as e:
            logger.error(f"Wallet state update error: {e}")
            return False

