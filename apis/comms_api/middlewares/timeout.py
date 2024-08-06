import asyncio
import re

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from starlette.status import HTTP_408_REQUEST_TIMEOUT

from comms_api.models.error import ErrorResponse

DEFAULT_TIMEOUT = 10

timeouts = {
    '/authentication': 20,
    '/commands': 60,
    '/commands/results': 15,
    '/events/stateful': 30,
    '/events/stateless': 5,
    '/files': 15
}


class TimeoutMiddleware(BaseHTTPMiddleware):
    """Middleware to set endpoint-specific timeouts."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Wait for the next request or timeout.

        Parameters
        ----------
        request : Request
            HTTP Request received.
        call_next :  RequestResponseEndpoint
            Endpoint callable to be executed.

        Returns
        -------
        Response
            Endpoint response.
        """
        path = re.sub(r'/api/.*/', '/', request.url.path)
        timeout = timeouts.get(path, DEFAULT_TIMEOUT)

        try:
            return await asyncio.wait_for(call_next(request), timeout=timeout)
        except asyncio.TimeoutError:
            return ErrorResponse(
                message='Request exceeded the processing time limit',
                status_code=HTTP_408_REQUEST_TIMEOUT,
            )
