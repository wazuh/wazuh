import asyncio
import logging
from functools import wraps

from fastapi import status

from comms_api.routers.exceptions import HTTPError

logger = logging.getLogger('wazuh-comms-api')


DEFAULT_TIMEOUT = 10


def timeout(seconds: float = DEFAULT_TIMEOUT):
    """Timeout decorator to set endpoint-specific timeouts."""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await asyncio.wait_for(func(*args, **kwargs), timeout=seconds)
            except asyncio.TimeoutError:
                logger.error('Timeout executing API request')
                raise HTTPError(
                    message='Request exceeded the processing time limit',
                    status_code=status.HTTP_408_REQUEST_TIMEOUT,
                )

        return wrapper

    return decorator
