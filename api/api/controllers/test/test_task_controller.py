import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from aiohttp import web_response

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from api.controllers.task_controller import get_tasks_status
        from wazuh import task
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', [{'token_info': {'rbac_policies': 'rbac_policies_value'}}])
async def test_task_controller(mock_request):
    """Test all task_controller endpoints"""
    async def test_get_tasks_status():
        calls = [call(f=task.get_task_status,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_tasks_status(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    # Function list containing all sub tests declared above.
    functions = [test_get_tasks_status()
                 ]
    for test_funct in functions:
        with patch('api.controllers.task_controller.DistributedAPI.__init__', return_value=None) as mock_dapi:
            with patch('api.controllers.task_controller.DistributedAPI.distribute_function',
                       return_value=AsyncMock()) as mock_dfunc:
                with patch('api.controllers.task_controller.raise_if_exc', return_value={}) as mock_exc:
                    await test_funct
