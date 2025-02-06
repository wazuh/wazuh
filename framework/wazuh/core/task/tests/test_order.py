from dataclasses import asdict
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from wazuh.core import common
from wazuh.core.engine.base import APPLICATION_JSON
from wazuh.core.exception import WazuhIndexerError
from wazuh.core.indexer.models.commands import Command, Source, Status, Target, TargetType
from wazuh.core.indexer.utils import convert_enums
from wazuh.core.task.order import get_orders


@pytest.mark.parametrize(
    'comms_api_response,update_command',
    (
        [{'commands': [{'order_id': 'test'}]}, True],
        [{'commands': []}, False],
    ),
)
@pytest.mark.parametrize('status_code,log_error', ([200, False], (400, True)))
@pytest.mark.parametrize('pending_commands', [True, False])
@patch('wazuh.core.task.order.httpx.AsyncClient.post')
@patch('wazuh.core.task.order.httpx.AsyncHTTPTransport')
@patch('asyncio.sleep')
@patch('wazuh.core.indexer.CentralizedConfig')
@patch('wazuh.core.indexer.create_indexer')
async def test_get_orders(
    create_indexer_mock,
    config_mock,
    sleep_mock,
    transport_mock,
    client_mock,
    pending_commands,
    status_code,
    log_error,
    comms_api_response,
    update_command,
):
    """Check the correct functionality of the `get_orders` function."""
    commands_list = (
        [
            Command(
                document_id='test',
                request_id='test',
                order_id='test',
                source=Source.SERVICES.value,
                user='test',
                target=Target(id='test', type=TargetType.AGENT.value),
                timeout=1,
                status=Status.PENDING,
            )
        ]
        if pending_commands
        else []
    )

    get_commands_mock = AsyncMock(return_value=commands_list)
    update_commands_status_mock = AsyncMock()
    create_indexer_mock.return_value.commands_manager.get_commands = get_commands_mock
    create_indexer_mock.return_value.commands_manager.update_commands_status = update_commands_status_mock

    client_mock.return_value = MagicMock(**{'status_code': status_code, 'json.return_value': comms_api_response})

    sleep_mock.side_effect = (None, StopAsyncIteration)
    logger_mock = MagicMock()

    with pytest.raises(StopAsyncIteration):
        await get_orders(logger_mock)

    transport_mock.assert_called_with(uds=common.COMMS_API_SOCKET_PATH)
    get_commands_mock.assert_called_once_with(Status.PENDING)

    if pending_commands:
        client_mock.assert_called_with(
            url='http://localhost/api/v1/commands',
            json={'commands': [asdict(command, dict_factory=convert_enums) for command in commands_list]},
            headers={'Accept': APPLICATION_JSON, 'Content-Type': APPLICATION_JSON},
        )
    else:
        client_mock.assert_not_called()

    if log_error and pending_commands:
        logger_mock.error.assert_called_with(f'Post orders failed: 400 - {comms_api_response}')
    else:
        logger_mock.error.assert_not_called()

    if not log_error and pending_commands:
        if update_command:
            update_commands_status_mock.assert_called_with(order_ids=['test'], status=Status.SENT.value)
        else:
            update_commands_status_mock.assert_not_called()


@pytest.mark.parametrize(
    'exception, message',
    [
        (httpx.ConnectError, 'Connection error'),
        (httpx.TimeoutException, 'Timeout error'),
        (WazuhIndexerError, 2200),
    ],
)
@patch('wazuh.core.task.order.httpx.AsyncClient.post')
@patch('wazuh.core.task.order.httpx.AsyncHTTPTransport')
@patch('asyncio.sleep')
@patch('wazuh.core.indexer.CentralizedConfig')
@patch('wazuh.core.indexer.create_indexer')
async def test_get_orders_ko(
    create_indexer_mock, config_mock, sleep_mock, transport_mock, client_mock, exception, message
):
    """Check the error handling of the `get_orders` method."""
    commands_list = [
        Command(
            document_id='test',
            request_id='test',
            order_id='test',
            source=Source.SERVICES,
            user='test',
            target=Target(id='test', type=TargetType.AGENT),
            timeout=1,
            status=Status.PENDING,
        )
    ]
    commands_mock = AsyncMock(return_value=commands_list)
    create_indexer_mock.return_value.commands_manager.get_commands = commands_mock
    client_mock.side_effect = exception(message)

    sleep_mock.side_effect = (None, StopAsyncIteration)
    logger_mock = MagicMock()

    with pytest.raises(StopAsyncIteration):
        await get_orders(logger_mock)

    transport_mock.assert_called_with(uds=common.COMMS_API_SOCKET_PATH)
    commands_mock.assert_called_once_with(Status.PENDING)

    if exception is WazuhIndexerError:
        message = 'Error 2200 - Could not connect to the indexer'
    logger_mock.error.assert_called_with(f'Failed sending the orders to the Communications API: {message}')
