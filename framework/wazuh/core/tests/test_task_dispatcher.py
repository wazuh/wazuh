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
    f = MagicMock()
    f.__name__ = 'default_function_name'
    return f


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


@pytest.mark.asyncio
@patch('wazuh.core.task_dispatcher.TaskDispatcher.execute_local_request', new_callable=AsyncMock)
async def test_execute_function_jsondecode_error(mock_exec, funct, logger):
    """Test that JSONDecodeError raised by `execute_local_request` is handled and returns WazuhInternalError(3036)."""
    mock_exec.side_effect = json.decoder.JSONDecodeError('msg', '', 0)
    dispatcher = TaskDispatcher(f=funct, logger=logger, debug=False)

    result = await dispatcher.execute_function()

    assert isinstance(result, exception.WazuhInternalError)
    assert result.code == 3036
    logger.error.assert_called_once_with(result.message)


@pytest.mark.asyncio
@patch('wazuh.core.task_dispatcher.TaskDispatcher.execute_local_request', new_callable=AsyncMock)
async def test_execute_function_wazuh_internal_error(mock_exec, funct, logger):
    """Test that WazuhInternalError is caught and returned."""
    err = exception.WazuhInternalError(3027)
    mock_exec.side_effect = err
    dispatcher = TaskDispatcher(f=funct, logger=logger, debug=False)

    result = await dispatcher.execute_function()

    assert result == err
    logger.error.assert_called_once_with(exception.WazuhInternalError.ERRORS[3027], exc_info=True)


@pytest.mark.asyncio
@patch('wazuh.core.task_dispatcher.TaskDispatcher.debug_log')
@patch('wazuh.core.task_dispatcher.TaskDispatcher.execute_local_request', new_callable=AsyncMock)
async def test_execute_function_wazuh_error(mock_exec, mock_debug_log, funct, logger):
    """Test that WazuhError (not internal) is caught and returned."""
    err = exception.WazuhResourceNotFound(1000, 'whatever')
    mock_exec.side_effect = err
    dispatcher = TaskDispatcher(f=funct, logger=logger, debug=False)

    result = await dispatcher.execute_function()

    assert result == err
    logger.error.assert_not_called()


@pytest.mark.asyncio
@patch('wazuh.core.task_dispatcher.TaskDispatcher.debug_log')
@patch('wazuh.core.task_dispatcher.TaskDispatcher.execute_local_request', new_callable=AsyncMock)
async def test_execute_function_unhandled_exception(mock_exec, mock_debug_log, funct, logger):
    """Test that unhandled exceptions are caught and wrapped as WazuhInternalError(1000)."""
    mock_exec.side_effect = RuntimeError('unexpected')
    dispatcher = TaskDispatcher(f=funct, logger=logger, debug=False)

    result = await dispatcher.execute_function()

    assert isinstance(result, exception.WazuhInternalError)
    assert result.code == 1000
    logger.error.assert_called_once_with('Unhandled exception: unexpected', exc_info=True)


@pytest.mark.asyncio
@patch('wazuh.core.task_dispatcher.TaskDispatcher.execute_local_request', new_callable=AsyncMock)
async def test_execute_function_jsondecode_error_debug_true(mock_exec, funct, logger):
    """Test that JSONDecodeError is raised when debug=True."""
    mock_exec.side_effect = json.decoder.JSONDecodeError('msg', '', 0)
    dispatcher = TaskDispatcher(f=funct, logger=logger, debug=True)

    with pytest.raises(json.decoder.JSONDecodeError):
        await dispatcher.execute_function()


@pytest.mark.asyncio
@patch('wazuh.core.task_dispatcher.TaskDispatcher.execute_local_request', new_callable=AsyncMock)
async def test_execute_function_wazuh_internal_error_debug_true(mock_exec, funct, logger):
    """Test that WazuhInternalError is raised when debug=True."""
    err = exception.WazuhInternalError(3027)
    mock_exec.side_effect = err
    dispatcher = TaskDispatcher(f=funct, logger=logger, debug=True)

    with pytest.raises(exception.WazuhInternalError) as exc:
        await dispatcher.execute_function()

    assert exc.value.code == 3027


@pytest.mark.asyncio
@patch('wazuh.core.task_dispatcher.TaskDispatcher.execute_local_request', new_callable=AsyncMock)
async def test_execute_function_unhandled_exception_debug_true(mock_exec, funct, logger):
    """Test that unhandled exception is raised when debug=True."""
    mock_exec.side_effect = RuntimeError('unexpected')
    dispatcher = TaskDispatcher(f=funct, logger=logger, debug=True)

    with pytest.raises(RuntimeError) as exc:
        await dispatcher.execute_function()

    assert str(exc.value) == 'unexpected'


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
async def test_execute_local_request_handle_agent_wildcard(mock_time, mock_debug_log, mock_run_local, funct, logger):
    """Test `execute_local_request` remove agents wildcard."""
    mock_time.side_effect = [10, 15]
    funct_kwargs = {'param': 'param-value', 'agent_list': '*'}
    dispatcher = TaskDispatcher(f=funct, f_kwargs=funct_kwargs, logger=logger, is_async=True)
    mock_run_local.return_value = 'retval'

    result = await dispatcher.execute_local_request()

    expected_run_local_f_fkwords_index = 1
    assert mock_run_local.call_args.args[expected_run_local_f_fkwords_index] == {'param': 'param-value'}
    assert result == 'retval'
    mock_debug_log.assert_has_calls(
        [
            call(f'Starting to execute request `{funct.__name__}` locally'),
            call(f'Finished executing request `{funct.__name__}` locally'),
            call(f'Time calculating `{funct.__name__}` request result: 5.000s'),
        ]
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    'pool_key, func_name',
    [('thread_pool', 'any_func'), ('authentication_pool', 'check_token'), ('process_pool', 'non_matching_func')],
)
@patch('wazuh.core.task_dispatcher.asyncio.get_event_loop')
@patch('wazuh.core.task_dispatcher.TaskDispatcher.debug_log')
@patch('wazuh.core.task_dispatcher.time.time')
async def test_execute_local_request_sync(mock_time, mock_debug_log, mock_get_loop, funct, logger, pool_key, func_name):
    """Test sync execution flow with timing and debug logging."""
    mock_time.side_effect = [10, 15]
    funct.__name__ = func_name

    dispatcher = TaskDispatcher(f=funct, logger=logger, is_async=False)

    loop = MagicMock()
    loop.run_in_executor.return_value = AsyncMock(return_value='mocked_result')()
    mock_get_loop.return_value = loop

    with patch.dict('wazuh.core.task_dispatcher.pools', {pool_key: 'mocked_pool'}, clear=True):
        result = await dispatcher.execute_local_request()

        assert result == 'mocked_result'
        mock_debug_log.assert_has_calls(
            [
                call(f'Starting to execute request `{funct.__name__}` locally'),
                call(f'Finished executing request `{funct.__name__}` locally'),
                call(f'Time calculating `{funct.__name__}` request result: 5.000s'),
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
    mock_debug_log.assert_called_once_with(f'Starting to execute request `{funct.__name__}` locally')
    loop.run_in_executor.assert_called_once()


@patch('wazuh.core.task_dispatcher.common.rbac', new_callable=MagicMock)
@patch('wazuh.core.task_dispatcher.common.current_user', new_callable=MagicMock)
@patch('wazuh.core.task_dispatcher.common.origin_module', new_callable=MagicMock)
@patch('wazuh.core.task_dispatcher.common.rbac_manager', new_callable=MagicMock)
@patch('wazuh.core.task_dispatcher.common.reset_context_cache', new_callable=MagicMock)
def test_run_local_sets_contextvars_and_returns_data(
    mock_reset, mock_rbac_manager, mock_origin_module, mock_current_user, mock_rbac, funct
):
    """Test that `run_local` sets contextvars, calls the function and resets the context cache."""
    f_kwargs = {'arg': 'val'}
    rbac_permissions = {'rule': 'allowed'}
    current_user_val = 'test-user'
    origin_module_val = 'test-module'
    rbac_manager_val = 'mock-manager'

    # Mocking the set method of ContextVar
    mock_rbac.set = MagicMock()
    mock_current_user.set = MagicMock()
    mock_origin_module.set = MagicMock()
    mock_rbac_manager.set = MagicMock()

    # Setup mock function to return a value
    funct.return_value = 'dummy-result'

    result = TaskDispatcher.run_local(
        f=funct,
        f_kwargs=f_kwargs,
        rbac_permissions=rbac_permissions,
        current_user=current_user_val,
        origin_module=origin_module_val,
        rbac_manager=rbac_manager_val,
    )

    assert result == 'dummy-result'
    funct.assert_called_once_with(**f_kwargs)
    mock_rbac.set.assert_called_once_with(rbac_permissions)
    mock_current_user.set.assert_called_once_with(current_user_val)
    mock_origin_module.set.assert_called_once_with(origin_module_val)
    mock_rbac_manager.set.assert_called_once_with(rbac_manager_val)
    mock_reset.assert_called_once()
