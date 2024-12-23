import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
from fastapi import FastAPI, Request
from freezegun import freeze_time
from starlette.applications import Starlette

from comms_api.middlewares.logging import LoggingMiddleware, log_request, log_request_debug


@freeze_time(datetime(1970, 1, 1, 0, 0, 1))
async def test_log_request():
    """Test log request calls."""
    expected_time = datetime(1970, 1, 1, 0, 0, 0).timestamp()
    agent_uuid = '1'
    method, path = 'POST', '/api/v1'
    query, elapsed_time, status_code = {'pretty': True}, 1.0, 200
    body = {}
    body.update({'test': 'test'})

    json_info = {
        'http_method': method,
        'uri': f'{method} {path}',
        'parameters': query,
        'body': body,
        'time': f'{elapsed_time:.3f}s',
        'status_code': status_code,
        'agent_uuid': agent_uuid,
    }

    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_req = MagicMock()
    mock_req.scope = {'path': path}
    mock_req.method = method
    mock_req.query_params = query
    mock_req.json = AsyncMock(return_value=body)
    mock_req.state.agent_uuid = agent_uuid

    with patch('comms_api.middlewares.logging.logger') as logger_mock:
        logger_mock.info = MagicMock()
        logger_mock.level = 1
        _ = await log_request(request=mock_req, response=mock_resp, start_time=expected_time)

        log_info = (
            f'({agent_uuid}) "{method} {path}" with parameters {json.dumps(query)} and body '
            f'{json.dumps(body)} done in {elapsed_time:.3f}s: {status_code}'
        )
        logger_mock.info.assert_has_calls(
            [call(log_info, extra={'log_type': 'log'}), call(json_info, extra={'log_type': 'json'})]
        )


async def test_log_request_debug():
    """Validate that the `log_request_debug` function works as expected."""
    request = Request(scope={'type': 'http', 'app': FastAPI(), 'headers': [(b'content-type', b'application/json')]})
    body = '{"id": "123"}'
    request._body = '\n'.join([body]).encode()

    with patch('comms_api.middlewares.logging.logger') as logger_mock:
        logger_mock.debug = MagicMock()
        _ = await log_request_debug(request=request, path='/events')

        logger_mock.debug.assert_has_calls(
            [
                call("Request headers: {'content-type': 'application/json'}", extra={'log_type': 'log'}),
                call(f'Request body stream: {body}', extra={'log_type': 'log'}),
            ]
        )


@pytest.mark.asyncio
@freeze_time(datetime(1970, 1, 1, 0, 0, 0))
async def test_logging_middleware():
    """Test logging middleware."""
    middleware = LoggingMiddleware(Starlette())
    expected_time = datetime(1970, 1, 1, 0, 0, 0).timestamp()
    body = {}
    body.update({'test': 'test'})
    mock_req = AsyncMock()
    mock_req.json = AsyncMock(return_value=body)
    mock_resp = MagicMock()
    call_next_mock = AsyncMock(return_value=mock_resp)

    with patch('comms_api.middlewares.logging.log_request') as mock_log_request:
        _ = await middleware.dispatch(mock_req, call_next_mock)
        mock_log_request.assert_called_once_with(mock_req, mock_resp, expected_time)
