import asyncio
import os
from pathlib import PosixPath
from unittest.mock import AsyncMock, patch

from asyncinotify import Mask
import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from api.constants import SECURITY_PATH
from api.signals import (
    cancel_signal_handler,
    clean_auth_keys_cache,
    lifespan_handler,
)

# Tests


@pytest.mark.asyncio
async def test_cancel_signal_handler_catch_cancelled_error_and_dont_rise():
    coroutine_mock = AsyncMock(side_effect=asyncio.CancelledError)
    await cancel_signal_handler(coroutine_mock)()

    coroutine_mock.assert_awaited_once()


@patch('api.signals.clean_auth_keys_cache')
@pytest.mark.asyncio
async def test_register_background_tasks(clean_auth_keys_cache_mock):
    class AwaitableMock(AsyncMock):
        def __await__(self):
            self.await_count += 1
            return iter([])

    with patch('api.signals.asyncio') as create_task_mock:
        create_task_mock.create_task.return_value = AwaitableMock(spec=asyncio.Task)
        create_task_mock.create_task.return_value.cancel = AsyncMock()

        with TestClient(Starlette(lifespan=lifespan_handler)):
            assert create_task_mock.create_task.call_count == 1

        assert create_task_mock.create_task.return_value.cancel.call_count == 1


@pytest.mark.asyncio
@patch('api.signals._private_key_path', new='/path/to/private.key')
@patch('api.signals._public_key_path', new='/path/to/public.key')
@patch('api.signals.generate_keypair.cache_clear')
@pytest.mark.parametrize(
    'filename',
    ['/path/to/private.key', '/path/to/public.key', 'other_file.txt']
)
async def test_clean_auth_keys_cache(mock_generate_keypair_cache, filename):
    with patch('api.signals.Inotify') as inotify_mock:
        inotify_instance = inotify_mock.return_value.__enter__.return_value
        event_mock = AsyncMock()
        event_mock.path = PosixPath(filename)
        inotify_instance.__aiter__.return_value = [event_mock]

        task = asyncio.create_task(
            clean_auth_keys_cache()
        )
        await asyncio.sleep(1)

        task.cancel()

        inotify_instance.add_watch.assert_called_with(
            SECURITY_PATH, Mask.MODIFY | Mask.CREATE
        )
        if filename in {'/path/to/private.key', '/path/to/public.key'}:
            mock_generate_keypair_cache.assert_called_once()
        else:
            mock_generate_keypair_cache.assert_not_called()
