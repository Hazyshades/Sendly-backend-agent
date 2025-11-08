import logging
from typing import Any, Dict

import httpx

from config.settings import settings

logger = logging.getLogger(__name__)


class ElevenLabsService:
    base_url = "https://api.elevenlabs.io/v1/speech-to-text"

    async def transcribe(self, audio_bytes: bytes, filename: str = "audio.webm") -> Dict[str, Any]:
        if not audio_bytes:
            raise ValueError("Empty audio buffer")

        if not settings.ELEVENLABS_API_KEY:
            raise RuntimeError("ElevenLabs API key is not configured")

        headers = {"xi-api-key": settings.ELEVENLABS_API_KEY}
        files = {"file": (filename, audio_bytes, "audio/webm")}
        data = {"model_id": "scribe_v1"}

        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(self.base_url, headers=headers, files=files, data=data)
            response.raise_for_status()
            payload: Dict[str, Any] = response.json()
            logger.info("Speech-to-text transcription completed")
            return payload


elevenlabs_service = ElevenLabsService()


