from unittest.mock import call, patch

import uvicorn

from wazuh.core.cluster.unix_server.server import start_unix_server, SERVER_UNIX_SOCKET_PATH
from wazuh.core.cluster.unix_server.config import get_config


@patch('wazuh.core.cluster.unix_server.server.FastAPI')
@patch('wazuh.core.cluster.unix_server.server.APIRouter')
@patch('wazuh.core.cluster.unix_server.server.Thread')
def test_start_unix_server(mock_thread, router_mock, fastapi_mock):
    """Validate that `start_unix_server` function works as expected."""
    start_unix_server()

    router_mock.assert_has_calls([
        call(prefix='/api/v1'),
        call().add_api_route('/config', get_config, methods=['GET'])
    ])
    mock_thread.assert_has_calls([
        call(target=uvicorn.run, kwargs={'app': fastapi_mock(), 'uds': SERVER_UNIX_SOCKET_PATH}, daemon=True),
        call().start()
    ])
