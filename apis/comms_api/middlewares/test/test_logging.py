import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
from freezegun import freeze_time
from starlette.applications import Starlette

from comms_api.middlewares.logging import LoggingMiddleware, log_request


@freeze_time(datetime(1970, 1, 1, 0, 0, 0))
async def test_log_request():
    """Test log request calls."""
    expected_time = datetime(1970, 1, 1, 0, 0, 0).timestamp()
    remote, method, path = '1.1.1.1', 'POST', '/api/v1'
    query, elapsed_time, status_code =  {'pretty': True}, 1.01, 200
    body = {}
    body.update({'test': 'test'})

    json_info = {
        'ip': remote,
        'http_method': method,
        'uri': f'{method} {path}',
        'parameters': query,
        'body': body,
        'time': f'{elapsed_time:.3f}s',
        'status_code': status_code
    }

    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_req = MagicMock()
    mock_req.client.host = remote
    mock_req.scope = {'path': path}
    mock_req.method = method
    mock_req.query_params = query
    mock_req.json = AsyncMock(return_value=body)

    with patch('api.alogging.logger') as log_info_mock:
        log_info_mock.info = MagicMock()
        log_info_mock.level = 1
        _ = await log_request(request=mock_req, response=mock_resp, start_time=expected_time)

        log_info = f'{remote} "{method} {path}" with parameters {json.dumps(query)} and body ' \
                    f'{json.dumps(body)} done in {elapsed_time:.3f}s: {status_code}'
        log_info_mock.info.has_calls([call(log_info, {'log_type': 'log'}),
                                      call(json_info, {'log_type': 'json'})])


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
