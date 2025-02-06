from asyncio import sleep

import pytest
from fastapi import status

from comms_api.routers.exceptions import HTTPError
from comms_api.routers.utils import DEFAULT_TIMEOUT, timeout


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

    timeout_seconds = timeout_seconds if timeout_seconds is not None else DEFAULT_TIMEOUT
    if timeout_seconds > sleep_seconds:
        result = await f()
        assert result is True
    else:
        message = 'Request exceeded the processing time limit'
        with pytest.raises(HTTPError, match=fr'{status.HTTP_408_REQUEST_TIMEOUT}: {message}'):
            _ = await f()
