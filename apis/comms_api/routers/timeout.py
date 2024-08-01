import asyncio
from functools import wraps

from fastapi import status

from comms_api.models.error import ErrorResponse

DEFAULT_TIMEOUT = 10

def timeout(seconds: float = DEFAULT_TIMEOUT):
    """Timeout decorator to set endpoint-specific timeouts."""

    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await asyncio.wait_for(func(*args, **kwargs), timeout=seconds)
            except asyncio.TimeoutError:
                return ErrorResponse(
                    message='Request exceeded the processing time limit',
                    status_code=status.HTTP_408_REQUEST_TIMEOUT,
                )

        return wrapper

    return decorator
