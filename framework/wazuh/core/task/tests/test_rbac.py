from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
from wazuh.core.exception import WazuhError, WazuhIndexerError
from wazuh.core.task.rbac import TARGET_ID, get_rbac_info


@patch('wazuh.core.task.rbac.CommandsManager', new_callable=AsyncMock)
@patch('wazuh.core.task.rbac.RBACManager', new_callable=AsyncMock)
async def test_get_rbac_info(rbac_manager_mock, commands_manager_mock):
    """Check the correct functionality of the `get_rbac_info` function."""
    logger_mock = MagicMock()
    commands_manager_mock.get_commands.side_effect = (None, StopAsyncIteration)
    rbac_manager_mock.return_value.update = AsyncMock()

    with pytest.raises(StopAsyncIteration):
        await get_rbac_info(logger_mock, commands_manager_mock, rbac_manager_mock)

    commands_manager_mock.get_commands.assert_has_calls([call(TARGET_ID), call(TARGET_ID)])
    rbac_manager_mock.update.assert_has_calls([call(), call()])


@pytest.mark.parametrize(
    'exception, code',
    [
        (WazuhIndexerError, 2200),
        (WazuhError, 1761),
    ],
)
@patch('wazuh.core.task.rbac.CommandsManager', new_callable=AsyncMock)
@patch('wazuh.core.task.rbac.RBACManager', new_callable=AsyncMock)
async def test_get_rbac_info_ko(rbac_manager_mock, commands_manager_mock, exception, code):
    """Check the error handling of the `get_rbac_info` method."""
    rbac_manager_mock.update.side_effect = (exception(code), StopAsyncIteration)
    logger_mock = MagicMock()

    with pytest.raises(StopAsyncIteration):
        await get_rbac_info(logger_mock, commands_manager_mock, rbac_manager_mock)

    if exception is WazuhIndexerError:
        code = f'Error {code} - Could not connect to the indexer'
    elif exception is WazuhError:
        code = f'Error {code} - Error sending request to the indexer'

    logger_mock.error.assert_called_with(f'Failed updating RBAC information: {code}', exc_info=False)
