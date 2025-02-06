from unittest.mock import AsyncMock, MagicMock

from fastapi import status
from wazuh.core.indexer.models.commands import Command, Status

from comms_api.core.unix_server.commands import post_commands
from comms_api.models.commands import Commands


async def test_post_commands():
    """Verify that the `post_commands` handler works as expected."""
    request = MagicMock()
    commands_manager_mock = AsyncMock()
    request.app.state.commands_manager = commands_manager_mock
    commands = Commands(commands=[Command(document_id='UB2jVpEBYSr9jxqDgXAD', status=Status.PENDING)])

    response = await post_commands(request, commands)

    commands_manager_mock.add_commands.assert_called_once_with(commands.commands)
    assert response.status_code == status.HTTP_200_OK
    assert response.body == b''
