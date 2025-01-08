from dataclasses import asdict
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from wazuh.core import common
from wazuh.core.engine.base import APPLICATION_JSON
from wazuh.core.indexer.models.commands import Command, Target, TargetType, Source, Status
from wazuh.core.indexer.utils import convert_enums
from wazuh.core.task.order import get_orders

@pytest.mark.parametrize('status_code,log_error', ([200, False], (400, True)))
@patch('wazuh.core.task.order.httpx.AsyncClient.post')
@patch('wazuh.core.task.order.httpx.AsyncHTTPTransport')
@patch('asyncio.sleep')
@patch('wazuh.core.indexer.CentralizedConfig')
@patch('wazuh.core.indexer.create_indexer')
async def test_get_orders(
    create_indexer_mock, config_mock, sleep_mock, transport_mock, client_mock, status_code, log_error
):
    """Check the correct functionality of the `get_orders` function."""

    commands_list = [
        Command(
            document_id='test',
            request_id='test',
            order_id='test',
            source=Source.SERVICES.value,
            user='test',
            target=Target(id='test', type=TargetType.AGENT.value),
            timeout=1,
            status=Status.PENDING.value
        )
    ]

    commands_mock = AsyncMock(return_value=commands_list)
    create_indexer_mock.return_value.commands_manager.get_commands = commands_mock
    client_mock.return_value = MagicMock(**{'status_code': status_code, 'json.return_value': '{}'})

    sleep_mock.side_effect = (None, StopAsyncIteration)
    logger_mock = MagicMock()

    with pytest.raises(StopAsyncIteration):
        await get_orders(logger_mock)

    transport_mock.assert_called_with(uds=common.COMMS_API_SOCKET_PATH)
    commands_mock.assert_called_once_with(Status.PENDING.value)
    client_mock.assert_called_with(
        url='http://localhost/api/v1/commands',
        json={"commands": [asdict(command, dict_factory=convert_enums) for command in commands_list]},
        headers={'Accept': APPLICATION_JSON, 'Content-Type': APPLICATION_JSON}
    )

    if log_error:
        logger_mock.error.assert_called_with('Post orders failed: 400 - {}')


@pytest.mark.parametrize(
    'exception, message',
    [(httpx.ConnectError, 'Connection error'), (httpx.TimeoutException, 'Timeout error')]
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

    commands_mock = AsyncMock(return_value=[])
    create_indexer_mock.return_value.commands_manager.get_commands = commands_mock
    client_mock.side_effect = exception(message)

    sleep_mock.side_effect = (None, StopAsyncIteration)
    logger_mock = MagicMock()

    with pytest.raises(StopAsyncIteration):
        await get_orders(logger_mock)

    transport_mock.assert_called_with(uds=common.COMMS_API_SOCKET_PATH)
    commands_mock.assert_called_once_with(Status.PENDING.value)

    logger_mock.error.assert_called_with('An error occurs sending the orders to the Communications API :', message)