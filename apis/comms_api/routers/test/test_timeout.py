from asyncio import sleep

import pytest
from fastapi import status

from comms_api.models.error import ErrorResponse
from comms_api.routers.timeout import DEFAULT_TIMEOUT, timeout

@pytest.mark.asyncio
@pytest.mark.parametrize('timeout_seconds,sleep_seconds', [
    (1, 0.1),
    (0.5, 0.1),
    (None, 0.1),
    (1, 0),
    (0.1, 0.2)
])
async def test_timeout(timeout_seconds, sleep_seconds):
    """Verify that timeout decorator works as expected."""

    @timeout(timeout_seconds)
    async def f() -> bool:
        await sleep(sleep_seconds)
        return True

    result = await f()
    timeout_seconds = timeout_seconds if timeout_seconds is not None else DEFAULT_TIMEOUT
    if timeout_seconds > sleep_seconds:
        assert result == True
    else:
        assert isinstance(result, ErrorResponse)
        assert result.message == 'Request exceeded the processing time limit'
        assert result.code == status.HTTP_408_REQUEST_TIMEOUT
        assert result.status_code == status.HTTP_408_REQUEST_TIMEOUT
