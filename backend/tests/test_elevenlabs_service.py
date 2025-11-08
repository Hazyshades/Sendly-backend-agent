import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from config.settings import settings
from services.elevenlabs_service import ElevenLabsService


class ElevenLabsServiceTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.service = ElevenLabsService()
        self.previous_key = settings.ELEVENLABS_API_KEY
        settings.ELEVENLABS_API_KEY = "test-key"

    async def asyncTearDown(self) -> None:
        settings.ELEVENLABS_API_KEY = self.previous_key

    async def test_transcribe_success(self) -> None:
        mock_response = MagicMock()
        mock_response.json.return_value = {"text": "transfer 10 usdc"}
        mock_response.raise_for_status.return_value = None

        async_post = AsyncMock(return_value=mock_response)

        with patch("services.elevenlabs_service.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = async_post

            result = await self.service.transcribe(b"\x00\x01", "audio.webm")

        async_post.assert_awaited_once()
        self.assertEqual(result["text"], "transfer 10 usdc")

    async def test_transcribe_with_empty_payload_raises(self) -> None:
        with self.assertRaises(ValueError):
            await self.service.transcribe(b"", "audio.webm")

    async def test_transcribe_without_api_key_raises(self) -> None:
        settings.ELEVENLABS_API_KEY = ""

        with self.assertRaises(RuntimeError):
            await self.service.transcribe(b"\x00\x01", "audio.webm")


