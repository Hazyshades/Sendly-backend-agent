import unittest
from datetime import datetime, timezone
from importlib import util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

_SUPABASE_SERVICE_PATH = (
    Path(__file__).resolve().parent.parent / "services" / "supabase_service.py"
)
_spec = util.spec_from_file_location("supabase_service_for_tests", _SUPABASE_SERVICE_PATH)
supabase_module = util.module_from_spec(_spec)
assert _spec is not None and _spec.loader is not None
_spec.loader.exec_module(supabase_module)

SupabaseService = supabase_module.SupabaseService
build_functions_base_url = supabase_module.build_functions_base_url
filter_due_schedules = supabase_module.filter_due_schedules


class SupabaseServiceHelpersTest(unittest.TestCase):
    def test_build_functions_base_url_valid(self) -> None:
        result = build_functions_base_url("https://project.supabase.co")
        self.assertEqual(result, "https://project.functions.supabase.co")

    def test_build_functions_base_url_invalid(self) -> None:
        self.assertIsNone(build_functions_base_url("https://example.com"))

    def test_filter_due_schedules_filters_correctly(self) -> None:
        now = datetime(2025, 11, 8, 12, 6, tzinfo=timezone.utc)
        due_job = {
            "id": "job-1",
            "status": "active",
            "paused": False,
            "next_run_at": "2025-11-08T12:05:00+00:00",
            "start_at": "2025-11-08T12:00:00+00:00",
            "total_runs": 0,
        }
        skipped_job = {
            "id": "job-2",
            "status": "paused",
            "paused": True,
            "next_run_at": "2025-11-08T12:05:00+00:00",
            "start_at": "2025-11-08T12:00:00+00:00",
        }

        result = filter_due_schedules([due_job, skipped_job], now)

        self.assertEqual([due_job], result)


class MockQuery:
    def __init__(self, data):
        self._data = data

    def select(self, *args, **kwargs):
        return self

    def lte(self, *args, **kwargs):
        return self

    def order(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def execute(self):
        return SimpleNamespace(data=self._data)


class SupabaseServiceAsyncTest(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.create_client_patcher = patch.object(supabase_module, "create_client")
        self.mock_create_client = self.create_client_patcher.start()
        self.mock_client = MagicMock()
        self.mock_create_client.return_value = self.mock_client

        self.service = SupabaseService("https://project.supabase.co", "service-key")

    async def asyncTearDown(self) -> None:
        self.create_client_patcher.stop()

    async def test_fetch_due_schedules_returns_filtered_jobs(self) -> None:
        now = datetime(2025, 11, 8, 12, 6, tzinfo=timezone.utc)
        jobs = [
            {
                "id": "job-1",
                "status": "active",
                "paused": False,
                "next_run_at": "2025-11-08T12:05:00+00:00",
                "start_at": "2025-11-08T12:00:00+00:00",
                "total_runs": 0,
            },
            {
                "id": "job-2",
                "status": "inactive",
                "paused": False,
                "next_run_at": "2025-11-08T12:05:00+00:00",
            },
        ]

        self.mock_client.table.return_value = MockQuery(jobs)

        result = await self.service.fetch_due_schedules(now=now)

        self.assertEqual(1, len(result))
        self.assertEqual("job-1", result[0]["id"])

    async def test_trigger_schedule_run_success(self) -> None:
        mock_response = SimpleNamespace(status_code=200, text="{}")
        async_post = AsyncMock(return_value=mock_response)

        with patch("services.supabase_service.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = async_post
            result = await self.service.trigger_schedule_run("job-1")

        async_post.assert_awaited_once()
        self.assertTrue(result)

    async def test_trigger_schedule_run_failure(self) -> None:
        mock_response = SimpleNamespace(status_code=500, text="error")
        async_post = AsyncMock(return_value=mock_response)

        with patch("services.supabase_service.httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.post = async_post
            result = await self.service.trigger_schedule_run("job-1")

        async_post.assert_awaited_once()
        self.assertFalse(result)

