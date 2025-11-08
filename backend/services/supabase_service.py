import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx
from supabase import create_client, Client
from models.wallet import DeveloperWallet


def build_functions_base_url(supabase_url: str) -> Optional[str]:
    if not supabase_url:
        return None

    parsed = urlparse(supabase_url)

    if not parsed.scheme or not parsed.netloc:
        return None

    host = parsed.netloc

    if ".supabase.co" not in host:
        return None

    return f"{parsed.scheme}://{host.replace('.supabase.co', '.functions.supabase.co')}"


def parse_datetime(value: Optional[Any]) -> Optional[datetime]:
    if value is None:
        return None

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value

    if isinstance(value, str):
        normalized = value.strip()
        if not normalized:
            return None
        normalized = normalized.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed

    return None


def filter_due_schedules(jobs: Optional[List[Dict[str, Any]]], now: datetime) -> List[Dict[str, Any]]:
    if not jobs:
        return []

    due: List[Dict[str, Any]] = []

    for job in jobs:
        if job.get("paused") is True:
            continue

        status = job.get("status")
        if status and str(status).lower() != "active":
            continue

        next_run_at = parse_datetime(job.get("next_run_at"))
        if not next_run_at or next_run_at > now:
            continue

        start_at = parse_datetime(job.get("start_at"))
        if start_at and start_at > now:
            continue

        end_at = parse_datetime(job.get("end_at"))
        if end_at and end_at <= now:
            continue

        max_runs = job.get("max_runs")
        total_runs = job.get("total_runs") or 0
        if isinstance(max_runs, int) and total_runs >= max_runs:
            continue

        due.append(job)

    return due


logger = logging.getLogger(__name__)


class SupabaseService:
    
    def __init__(self, url: str, service_role_key: str):
        self.url = url
        self.service_role_key = service_role_key
        self.client: Optional[Client] = None
        self.functions_base_url: Optional[str] = build_functions_base_url(url)
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

    async def fetch_due_schedules(
        self,
        now: Optional[datetime] = None,
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        if not self.client:
            logger.error("Supabase client is not initialized")
            return []

        current_time = now or datetime.now(timezone.utc)

        try:
            response = (
                self.client.table("scheduled_jobs")
                .select("*")
                .lte("next_run_at", current_time.isoformat())
                .order("next_run_at", desc=False)
                .limit(limit)
                .execute()
            )

            return filter_due_schedules(response.data, current_time)
        except Exception as exc:
            logger.error("Failed to fetch due schedules: %s", exc)
            return []

    async def trigger_schedule_run(self, job_id: str) -> bool:
        if not job_id:
            logger.error("trigger_schedule_run called without job_id")
            return False

        if not self.functions_base_url:
            logger.error("Functions base URL is not configured for SupabaseService")
            return False

        endpoint = f"{self.functions_base_url}/server/agent/schedules/{job_id}/run"
        headers = {
            "Authorization": f"Bearer {self.service_role_key}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(endpoint, headers=headers, json={})

            if response.status_code >= 400:
                logger.error(
                    "Failed to trigger schedule %s: status=%s body=%s",
                    job_id,
                    response.status_code,
                    response.text,
                )
                return False

            return True
        except Exception as exc:
            logger.error("Error triggering schedule %s: %s", job_id, exc)
            return False

