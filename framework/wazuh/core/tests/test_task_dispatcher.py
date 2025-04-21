import json
from concurrent.futures import process
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest
from wazuh.core import exception
from wazuh.core.results import WazuhResult
from wazuh.core.task_dispatcher import TaskDispatcher, WazuhJSONEncoder


@pytest.fixture
def logger():
    """Fixture that returns a MagicMock instance to simulate a logger."""
    return MagicMock()


@pytest.fixture
def funct():
    """Fixture that returns a MagicMock instance to simulate a callable function."""
    return MagicMock()


@pytest.mark.asyncio
@patch('wazuh.core.task_dispatcher.TaskDispatcher.debug_log')
@patch('wazuh.core.task_dispatcher.TaskDispatcher.execute_local_request', new_callable=AsyncMock)
async def test_execute_function_success(mock_exec, mock_debug_log, funct, logger):
    """Test that `execute_function` returns the expected result and logs parameters."""
    mock_exec.return_value = WazuhResult({'result': 'result-value'})
    funct_kwargs = {'param': 'param-value'}
    dispatcher = TaskDispatcher(f=funct, logger=logger, f_kwargs=funct_kwargs)

    result = await dispatcher.execute_function()

    assert result == WazuhResult({'result': 'result-value'})
    mock_debug_log.assert_called_once_with(f'Receiving parameters {funct_kwargs}')


@pytest.mark.asyncio
@patch('wazuh.core.task_dispatcher.TaskDispatcher.debug_log')
@patch('wazuh.core.task_dispatcher.TaskDispatcher.execute_local_request', new_callable=AsyncMock)
async def test_execute_function_masks_password(mock_exec, mock_debug_log, funct, logger):
    """Test that passwords are masked in parameter logging."""
    mock_exec.return_value = WazuhResult({'result': 'result-value'})
    funct_kwargs = {'param': 'param-value', 'password': 'password-value'}
    masked_kwargs = {**funct_kwargs, 'password': '****'}
    dispatcher = TaskDispatcher(f=funct, logger=logger, f_kwargs=funct_kwargs)

    await dispatcher.execute_function()

    mock_debug_log.assert_called_once_with(f'Receiving parameters {masked_kwargs}')


@pytest.mark.asyncio
@patch('wazuh.core.task_dispatcher.TaskDispatcher.execute_local_request', new_callable=AsyncMock)
async def test_execute_function_logs_token_nbf_time(mock_exec, funct, logger):
    """Test that `token_nbf_time` is logged correctly by the logger."""
    mock_exec.return_value = WazuhResult({'result': 'result-value'})
    funct_kwargs = {'param': 'param-value', 'token_nbf_time': 1234}
    dispatcher = TaskDispatcher(f=funct, logger=logger, f_kwargs=funct_kwargs)

    await dispatcher.execute_function()

    logger.debug.assert_called_with(f'Decoded token {funct_kwargs}')


@pytest.mark.asyncio
@patch('wazuh.core.task_dispatcher.TaskDispatcher.execute_local_request', new_callable=AsyncMock)
async def test_execute_function_handle_non_wazuh_return(mock_exec, funct, logger):
    """Test that `execute_function` wraps non-Wazuh return values into a WazuhResult."""
    mock_exec.return_value = 'non-json-return'
    dispatcher = TaskDispatcher(f=funct, logger=logger)

    result = await dispatcher.execute_function()

    assert result == WazuhResult({'message': 'non-json-return'})


def test_debug_log_as_wazuh_api(funct):
    """Test that `debug_log` uses `debug2` method when logger is 'wazuh-api'."""
    message = 'test message'
    logger = MagicMock(name='wazuh-api')
    logger.name = 'wazuh-api'
    dispatcher = TaskDispatcher(f=funct, logger=logger)

    dispatcher.debug_log(message)

    logger.debug2.assert_called_once_with(message)


def test_debug_log_as_not_wazuh_api(funct):
    """Test that `debug_log` uses standard `debug` method when logger is not 'wazuh-api'."""
    message = 'test message'
    logger = MagicMock(name='other-component')
    logger.name = 'other-component'
    dispatcher = TaskDispatcher(f=funct, logger=logger)

    dispatcher.debug_log(message)

    logger.debug.assert_called_once_with(message)


@pytest.mark.asyncio
@patch('wazuh.core.task_dispatcher.TaskDispatcher.run_local', new_callable=AsyncMock)
@patch('wazuh.core.task_dispatcher.TaskDispatcher.debug_log')
@patch('wazuh.core.task_dispatcher.time.time')
async def test_execute_local_request_async(mock_time, mock_debug_log, mock_run_local, funct, logger):
    """Test that `execute_local_request` calculates and logs execution time."""
    mock_time.side_effect = [10, 15]
    dispatcher = TaskDispatcher(f=funct, logger=logger, is_async=True)
    mock_run_local.return_value = 'retval'

    result = await dispatcher.execute_local_request()

    assert result == 'retval'
    mock_debug_log.assert_has_calls(
        [
            call('Starting to execute request locally'),
            call('Finished executing request locally'),
            call('Time calculating request result: 5.000s'),
        ]
    )


@pytest.mark.asyncio
@patch('wazuh.core.task_dispatcher.asyncio.get_event_loop')
@patch('wazuh.core.task_dispatcher.TaskDispatcher.debug_log')
@patch('wazuh.core.task_dispatcher.pools', {'thread_pool': 'fake_pool'})
@patch('wazuh.core.task_dispatcher.time.time')
async def test_execute_local_request_sync(mock_time, mock_debug_log, mock_get_loop, funct, logger):
    """Test sync execution flow with timing and debug logging."""
    mock_time.side_effect = [10, 15]
    dispatcher = TaskDispatcher(f=funct, logger=logger, is_async=False)

    loop = MagicMock()
    loop.run_in_executor.return_value = AsyncMock(return_value='mocked_result')()
    mock_get_loop.return_value = loop

    result = await dispatcher.execute_local_request()

    assert result == 'mocked_result'
    mock_debug_log.assert_has_calls(
        [
            call('Starting to execute request locally'),
            call('Finished executing request locally'),
            call('Time calculating request result: 5.000s'),
        ]
    )
    loop.run_in_executor.assert_called_once()


@pytest.mark.asyncio
@patch('wazuh.core.task_dispatcher.TaskDispatcher.run_local', new_callable=AsyncMock)
async def test_execute_local_request_timeout(mock_run_local, funct, logger):
    """Test that `execute_local_request` handles timeout and returns WazuhInternalError."""
    dispatcher = TaskDispatcher(f=funct, logger=logger, is_async=True)
    dispatcher.api_request_timeout = 0.0

    result = await dispatcher.execute_local_request()

    assert result == json.dumps(exception.WazuhInternalError(3021), cls=WazuhJSONEncoder)
    logger.error.assert_called_once_with(exception.WazuhException.ERRORS[3021], exc_info=False)


@pytest.mark.asyncio
@patch('wazuh.core.task_dispatcher.asyncio.get_event_loop')
@patch('wazuh.core.task_dispatcher.TaskDispatcher.debug_log')
@patch('wazuh.core.task_dispatcher.pools', {'thread_pool': 'fake_pool'})
async def test_execute_local_request_broken_process_pool(mock_debug_log, mock_get_loop, funct, logger):
    """Test handling of broken process pool."""
    dispatcher = TaskDispatcher(f=funct, logger=logger, is_async=False)

    exploding_task = AsyncMock()
    exploding_task.side_effect = process.BrokenProcessPool('Simulated crash')

    loop = MagicMock()
    loop.run_in_executor.return_value = exploding_task()
    mock_get_loop.return_value = loop

    result = await dispatcher.execute_local_request()

    assert result == json.dumps(exception.WazuhInternalError(901), cls=WazuhJSONEncoder)
    logger.error.assert_called_once_with(exception.WazuhException.ERRORS[901], exc_info=True)
    mock_debug_log.assert_called_once_with('Starting to execute request locally')
    loop.run_in_executor.assert_called_once()
