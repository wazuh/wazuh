from unittest.mock import MagicMock, patch

import pytest

from comms_api.models.commands import Commands
from comms_api.routers.commands import get_commands
from comms_api.routers.exceptions import HTTPError
from wazuh.core.exception import WazuhCommsAPIError, WazuhResourceNotFound
from wazuh.core.indexer.models.commands import Command, Status

COMMANDS = [Command(document_id='UB2jVpEBYSr9jxqDgXAD', status=Status.PENDING)]
TOKEN = 'token'
UUID = '01915801-4b34-7131-9d88-ff06ff05aefd'


@pytest.mark.asyncio
@patch('comms_api.routers.commands.pull_commands', return_value=COMMANDS)
@patch('comms_api.routers.commands.decode_token', return_value={'uuid': UUID})
@patch('comms_api.routers.commands.JWTBearer.__call__', return_value=TOKEN)
async def test_get_commands(jwt_bearer_mock, decode_token_mock, pull_commands_mock):
    """Verify that the `get_commands` handler works as expected."""
    response = await get_commands(TOKEN)

    pull_commands_mock.assert_called_once_with(UUID)
    assert response == Commands(commands=COMMANDS)


@pytest.mark.asyncio
@patch('comms_api.routers.commands.decode_token')
@pytest.mark.parametrize('exception', [
    WazuhCommsAPIError(2706),
    WazuhResourceNotFound(2202),
])
async def test_get_commands_ko(decode_token_mock, exception):
    """Verify that the `get_commands` handler catches exceptions successfully."""
    with patch('comms_api.routers.commands.pull_commands', MagicMock(side_effect=exception)):
        with pytest.raises(HTTPError, match=fr'{exception.code}: {exception.message}'):
            _ = await get_commands('')
