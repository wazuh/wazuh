from unittest.mock import MagicMock, call, patch

import uvicorn
from wazuh.core.unix_server.commands import post_commands
from wazuh.core.unix_server.server import HTTPUnixServer


@patch('wazuh.core.unix_server.server.APIRouter')
def test_http_unix_server_add_route(router_mock):
    """Validate that the `add_route` method works as expected."""
    commands_manager_mock = MagicMock()
    unix_server = HTTPUnixServer('test', commands_manager_mock)
    unix_server.add_route('/commands', post_commands, methods=['POST'])
    unix_server.start()

    router_mock.assert_has_calls(
        [
            call(prefix='/api/v1'),
            call().add_api_route(path='/commands', endpoint=post_commands, methods=['POST']),
        ],
    )


@patch('wazuh.core.unix_server.server.FastAPI')
@patch('wazuh.core.unix_server.server.Thread')
def test_http_unix_server_start(thread_mock, fastapi_mock):
    """Validate that the `start` method works as expected."""
    commands_manager_mock = MagicMock()
    socket_path = 'test'
    unix_server = HTTPUnixServer(socket_path, commands_manager_mock)
    unix_server.start()

    assert fastapi_mock().state.commands_manager == commands_manager_mock

    thread_mock.assert_has_calls(
        [
            call(target=uvicorn.run, kwargs={'app': fastapi_mock(), 'uds': socket_path}, daemon=True),
            call().start(),
        ]
    )
