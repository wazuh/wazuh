from unittest.mock import AsyncMock, patch

import pytest

from comms_api.core.commands import pull_commands
from wazuh.core.indexer import Indexer
from wazuh.core.indexer.models.commands import Command, Status

COMMAND_ID = 'UB2jVpEBYSr9jxqDgXAD'
COMMAND = Command(document_id=COMMAND_ID, status=Status.PENDING)
UPDATED_COMMAND = Command(document_id=COMMAND_ID, status=Status.SENT)
INDEXER = Indexer(host='host', user='wazuh', password='wazuh')
UUID = '01915801-4b34-7131-9d88-ff06ff05aefd'


@pytest.mark.asyncio
@patch('wazuh.core.indexer.create_indexer', return_value=INDEXER)
@patch('wazuh.core.indexer.commands.CommandsManager.get', return_value=[COMMAND])
@patch('wazuh.core.indexer.commands.CommandsManager.update', new_callable=AsyncMock)
async def test_pull_commands(commands_update_mock, commands_get_mock, create_indexer_mock):
    commands = await pull_commands(UUID)

    create_indexer_mock.assert_called_once()
    commands_get_mock.assert_called_once_with(UUID, Status.PENDING)
    commands_update_mock.assert_called_once_with([UPDATED_COMMAND])
    assert commands == [UPDATED_COMMAND]
