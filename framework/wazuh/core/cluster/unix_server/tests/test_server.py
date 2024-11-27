import pytest
from unittest.mock import call, patch

import uvicorn

from wazuh.core.cluster.unix_server.server import start_unix_server, get_log_config, SERVER_UNIX_SOCKET_PATH
from wazuh.core.cluster.unix_server.config import get_config


def test_get_log_config():
    """Validate that `get_log_config` function works as expected."""
    node = "test-node"
    expected_fmt = '%(asctime)s %(levelname)s: [test-node] [Config Server] %(message)s'
    expected_datefmt = '%Y/%m/%d %H:%M:%S'

    # Act
    result = get_log_config(node)

    # Assert
    assert result['formatters']['default']['fmt'] == expected_fmt
    assert result['formatters']['default']['datefmt'] == expected_datefmt

    # Verify all handlers use the 'default' formatter
    for handler in result['handlers'].values():
        if 'formatter' in handler:
            assert handler['formatter'] == 'default'


@patch('wazuh.core.cluster.unix_server.server.FastAPI')
@patch('wazuh.core.cluster.unix_server.server.APIRouter')
@patch('wazuh.core.cluster.unix_server.server.Thread')
def test_start_unix_server(mock_thread, router_mock, fastapi_mock):
    """Validate that `start_unix_server` function works as expected."""
    start_unix_server('Master')
    logging = get_log_config('Master')

    router_mock.assert_has_calls([
        call(prefix='/api/v1'),
        call().add_api_route('/config', get_config, methods=['GET'])
    ])
    mock_thread.assert_has_calls([
        call(target=uvicorn.run, kwargs={'app': fastapi_mock(), 'uds': SERVER_UNIX_SOCKET_PATH, 'log_config': logging},
             daemon=True),
        call().start()
    ])
