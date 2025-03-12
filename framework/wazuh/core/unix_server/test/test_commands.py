from unittest.mock import MagicMock

from wazuh.core.indexer.models.commands import Command, Status
from wazuh.core.unix_server.commands import Commands, post_commands


async def test_post_commands():
    """Verify that the `post_commands` handler works as expected."""
    request = MagicMock()
    commands = Commands(commands=[Command(document_id='UB2jVpEBYSr9jxqDgXAD', status=Status.PENDING)])

    commands_manager_mock = MagicMock()
    request.app.state.commands_manager = commands_manager_mock
    commands_manager_mock.add_commands.return_value = commands.commands

    response = await post_commands(request, commands)

    commands_manager_mock.add_commands.assert_called_once_with(commands.commands)
    assert response.commands == commands.commands
