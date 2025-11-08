import os
from typing import Optional
from dotenv import load_dotenv

load_dotenv()


class Settings:
    TELEGRAM_BOT_TOKEN: str = os.getenv('TELEGRAM_BOT_TOKEN', '')
    
    CIRCLE_API_KEY: str = os.getenv('CIRCLE_API_KEY', '')
    CIRCLE_ENTITY_SECRET: str = os.getenv('CIRCLE_ENTITY_SECRET', '')
    CIRCLE_WALLET_SET_ID: Optional[str] = os.getenv('CIRCLE_WALLET_SET_ID')
    
    SUPABASE_URL: str = os.getenv('SUPABASE_URL', '')
    SUPABASE_SERVICE_ROLE_KEY: str = os.getenv('SUPABASE_SERVICE_ROLE_KEY', '')
    
    PINATA_API_KEY: str = os.getenv('PINATA_API_KEY', '')
    PINATA_SECRET_KEY: str = os.getenv('PINATA_SECRET_KEY', '')
    
    AIMLAPI_API_KEY: str = os.getenv('AIMLAPI_API_KEY', '')
    OPENAI_API_KEY: str = os.getenv('OPENAI_API_KEY', '')
    
    ELEVENLABS_API_KEY: str = os.getenv('ELEVENLABS_API_KEY', '')
    
    ARC_TESTNET_RPC_URL: str = os.getenv('ARC_TESTNET_RPC_URL', 'https://rpc.arc-testnet.com')
    GIFT_CARD_CONTRACT_ADDRESS: str = os.getenv('GIFT_CARD_CONTRACT_ADDRESS', '')
    USDC_ADDRESS: str = os.getenv('USDC_ADDRESS', '')
    EURC_ADDRESS: str = os.getenv('EURC_ADDRESS', '')
    
    DEFAULT_BLOCKCHAIN: str = os.getenv('DEFAULT_BLOCKCHAIN', 'ARC-TESTNET')
    
    def validate(self) -> bool:
        required_fields = [
            'TELEGRAM_BOT_TOKEN',
            'CIRCLE_API_KEY',
            'CIRCLE_ENTITY_SECRET',
            'SUPABASE_URL',
            'SUPABASE_SERVICE_ROLE_KEY',
        ]
        
        missing_fields = [field for field in required_fields if not getattr(self, field)]
        
        if missing_fields:
            print(f"⚠️ Missing required environment variables: {', '.join(missing_fields)}")
            return False

        if not (self.AIMLAPI_API_KEY or self.OPENAI_API_KEY):
            print("⚠️ At least one of AIMLAPI_API_KEY or OPENAI_API_KEY must be set.")
            return False
        
        return True


settings = Settings()

