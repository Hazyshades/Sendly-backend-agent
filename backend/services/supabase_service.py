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

            logger.info("Wallet not found for user_id=%s", user_id)
            
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

    async def get_contacts(self, user_id: str) -> List[Dict[str, Any]]:
        if not self.client:
            logger.error("Supabase client is not initialized")
            return []

        try:
            telegram_id_normalized = user_id.lower()
            contact_user_id = telegram_id_normalized

            wallet = await self.get_wallet_by_user(telegram_id_normalized)
            if wallet and wallet.user_id:
                contact_user_id = wallet.user_id.lower()
            else:
                logger.info(
                    "Developer wallet not found for telegram_user_id=%s; falling back to telegram id",
                    telegram_id_normalized
                )

            response = (
                self.client.table("personal_contacts")
                .select("name, wallet, is_favorite")
                .eq("user_id", contact_user_id)
                .order("is_favorite", desc=True)
                .order("name", desc=False)
                .execute()
            )

            contacts: List[Dict[str, Any]] = []

            for row in response.data or []:
                wallet_value = row.get("wallet")
                contact = {
                    "name": row.get("name"),
                    "wallet": wallet_value,
                    "wallet_address": wallet_value,
                    "is_favorite": row.get("is_favorite", False),
                }
                contacts.append(contact)

            return contacts
        except Exception as e:
            logger.error(f"Error fetching contacts for user {user_id}: {e}")
            return []

    async def upsert_contact(self, user_id: str, name: str, wallet: str) -> bool:
        if not self.client:
            logger.error("Supabase client is not initialized")
            return False

        try:
            if not name.strip() or not wallet.strip():
                raise ValueError("Name and wallet must be provided")

            normalized_user_id = user_id.lower()
            normalized_name = name.strip()
            normalized_wallet = wallet.strip()

            existing_response = (
                self.client.table("personal_contacts")
                .select("is_favorite")
                .eq("user_id", normalized_user_id)
                .eq("name", normalized_name)
                .limit(1)
                .execute()
            )

            is_favorite = False

            if existing_response.data:
                existing_row = existing_response.data[0]
                is_favorite = existing_row.get("is_favorite", False)

            data = {
                "user_id": normalized_user_id,
                "name": normalized_name,
                "wallet": normalized_wallet,
                "is_favorite": is_favorite,
            }

            response = (
                self.client.table("personal_contacts")
                .upsert(data, on_conflict="user_id,name")
                .execute()
            )

            return bool(response.data)
        except Exception as e:
            logger.error(f"Error upserting contact for user {user_id}: {e}")
            return False

    async def delete_contact(self, user_id: str, name: str) -> bool:
        if not self.client:
            logger.error("Supabase client is not initialized")
            return False

        try:
            if not name.strip():
                raise ValueError("Name must be provided")

            response = (
                self.client.table("personal_contacts")
                .delete()
                .eq("user_id", user_id.lower())
                .eq("name", name.strip())
                .execute()
            )

            if response.data:
                return True

            count = getattr(response, "count", None)
            return bool(count)
        except Exception as e:
            logger.error(f"Error deleting contact for user {user_id}: {e}")
            return False

