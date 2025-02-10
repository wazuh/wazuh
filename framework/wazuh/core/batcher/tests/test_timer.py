from unittest.mock import patch

import pytest

from framework.wazuh.core.batcher.timer import TimerManager


@pytest.mark.asyncio
@patch('asyncio.sleep', return_value=None)  # Patches asyncio.sleep to return immediately
async def test_start_timer(mock_sleep):
    """Check that the `start_timer` method works as expected."""
    timer_manager = TimerManager(max_time_seconds=1)
    timer_manager.start_timer()

    await timer_manager.wait_timeout_event()

    mock_sleep.assert_called_once_with(1)
    assert timer_manager._timeout_event.is_set()


@pytest.mark.asyncio
@patch('asyncio.sleep', return_value=None)  # Patches asyncio.sleep to return immediately
async def test_reset_timer(mock_sleep):
    """Check that the `reset_timer` method works as expected."""
    timer_manager = TimerManager(max_time_seconds=5)
    timer_manager.start_timer()
    timer_manager.reset_timer()

    assert not timer_manager._timeout_event.is_set()
    assert timer_manager._timeout_task is None


@pytest.mark.asyncio
async def test_wait_timeout_event():
    """Check that the `wait_timeout_event` method works as expected."""
    timer_manager = TimerManager(max_time_seconds=1)
    timer_manager._timeout_event.set()
    wait_return = await timer_manager.wait_timeout_event()

    assert wait_return
