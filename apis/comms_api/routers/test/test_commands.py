from unittest.mock import MagicMock, patch

import pytest
from fastapi import status
from pydantic import ValidationError

from comms_api.models.commands import Commands, CommandsResults
from comms_api.routers.commands import get_commands, post_commands_results
from comms_api.routers.exceptions import HTTPError
from wazuh.core.exception import WazuhCommsAPIError, WazuhResourceNotFound
from wazuh.core.indexer.models.commands import Command, Result, Status

COMMANDS = [Command(id='UB2jVpEBYSr9jxqDgXAD', status=Status.PENDING)]
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


@pytest.mark.asyncio
@patch('comms_api.routers.commands.post_results')
async def test_post_commands_results(post_results_mock):
    """Verify that the `post_commands_results` handler works as expected."""
    results = [Result(id='id', status=Status.SUCCESS)]
    body = CommandsResults(results=results)
    response = await post_commands_results(body)

    post_results_mock.assert_called_once_with(results)
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_post_commands_results_ko():
    """Verify that the `post_commands_results` handler catches exceptions successfully."""
    exception = WazuhResourceNotFound(2202)
    results = [Result(id='id', status=Status.SUCCESS)]

    with patch('comms_api.routers.commands.post_results', MagicMock(side_effect=exception)):
        with pytest.raises(HTTPError, match=fr'{exception.code}: {exception.message}'):
            _ = await post_commands_results(CommandsResults(results=results))


@pytest.mark.asyncio
async def test_post_commands_results_body_ko():
    """Verify that the `post_commands_results` request body validation works as expected."""
    results = [Result(id='id', status=Status.SENT)]
    with pytest.raises(ValidationError):
        body = CommandsResults(results=results)
        await post_commands_results(body)
