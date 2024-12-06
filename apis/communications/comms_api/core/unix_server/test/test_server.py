from unittest.mock import call, patch, MagicMock

import uvicorn

from comms_api.core.unix_server.commands import post_commands
from comms_api.core.unix_server.server import start_unix_server, common


@patch('comms_api.core.unix_server.server.FastAPI')
@patch('comms_api.core.unix_server.server.APIRouter')
@patch('comms_api.core.unix_server.server.Thread')
def test_start_unix_server(mock_thread, router_mock, fastapi_mock):
    """Validate that `start_unix_server` works as expected."""
    commands_manager_mock = MagicMock()
    start_unix_server(commands_manager_mock)

    router_mock.assert_has_calls([
        call(prefix='/api/v1'),
        call().add_api_route('/commands', post_commands, methods=['POST'])
    ])
    mock_thread.assert_has_calls([
        call(target=uvicorn.run, kwargs={'app': fastapi_mock(), 'uds': common.COMMS_API_SOCKET_PATH}, daemon=True),
        call().start()
    ])
