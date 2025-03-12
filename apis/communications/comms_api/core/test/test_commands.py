from unittest.mock import AsyncMock, patch

import pytest
from wazuh.core.indexer.models.commands import Command, Status, Target, TargetType

from comms_api.core.commands import pull_commands

DOCUMENT_ID = 'UB2jVpEBYSr9jxqDgXAD'
AGENT_ID = '01915801-4b34-7131-9d88-ff06ff05aefd'
COMMAND = Command(document_id=DOCUMENT_ID, status=Status.PENDING, target=Target(id=AGENT_ID, type=TargetType.AGENT))


@pytest.mark.asyncio
@patch('comms_api.core.commands.CommandsManager')
async def test_pull_commands(commands_manager_mock):
    """Check that the `pull_commands` function works as expected."""
    get_commands_mock = AsyncMock(return_value=[COMMAND])
    commands_manager_mock.get_commands = get_commands_mock
    commands = await pull_commands(commands_manager_mock, AGENT_ID)

    assert commands == [COMMAND]
