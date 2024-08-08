import asyncio
from unittest.mock import MagicMock, patch

import pytest
from starlette.applications import Starlette
from starlette.status import HTTP_408_REQUEST_TIMEOUT

from comms_api.middlewares.timeout import DEFAULT_TIMEOUT, TimeoutMiddleware


@pytest.mark.asyncio
@pytest.mark.parametrize("endpoint,expected_timeout", [
    ('/authentication', 20), 
    ('/commands', 60),
    ('/commands/results', 15),
    ('/events/stateful', 30),
    ('/events/stateless', 5),
    ('/files', 15),
    ('/other', DEFAULT_TIMEOUT)
])
async def test_timeout_middleware(endpoint, expected_timeout):
    """Test timeout middleware."""
    middleware = TimeoutMiddleware(Starlette())
    mock_req = MagicMock()
    mock_req.url = MagicMock()
    mock_req.url.path = endpoint
    call_next_mock = MagicMock()

    with patch('asyncio.wait_for') as wait_for_mock:
        _ = await middleware.dispatch(request=mock_req, call_next=call_next_mock)
        wait_for_mock.assert_called_once_with(call_next_mock(mock_req), timeout=expected_timeout)


@pytest.mark.asyncio
async def test_timeout_middleware_ko():
    """Test timeout middleware exception handling."""
    middleware = TimeoutMiddleware(Starlette())
    mock_req = MagicMock()
    mock_req.url = MagicMock()
    mock_req.url.path = '/'
    call_next_mock = MagicMock()

    with patch('asyncio.wait_for', side_effect=asyncio.TimeoutError()):
        response = await middleware.dispatch(request=mock_req, call_next=call_next_mock)
        assert response.code == HTTP_408_REQUEST_TIMEOUT
        assert response.message == 'Request exceeded the processing time limit'
