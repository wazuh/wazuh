import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from aiohttp import web_response

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']

        from api.controllers.rootcheck_controller import (put_rootcheck,
                                                          delete_rootcheck,
                                                          get_rootcheck_agent,
                                                          get_last_scan_agent)
        from wazuh import rootcheck
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', [{'token_info': {'rbac_policies': 'value1'}}])
async def test_rootcheck_controller(mock_request):
    async def test_put_rootcheck():
        calls = [call(f=rootcheck.run,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      broadcasting=True,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await put_rootcheck(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_delete_rootcheck():
        calls = [call(f=rootcheck.clear,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await delete_rootcheck(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_rootcheck_agent():
        calls = [call(f=rootcheck.get_rootcheck_agent,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_rootcheck_agent(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_last_scan_agent():
        calls = [call(f=rootcheck.get_last_scan,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_last_scan_agent(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    functions = [test_put_rootcheck(),
                 test_delete_rootcheck(),
                 test_get_rootcheck_agent(),
                 test_get_last_scan_agent(),
                 ]
    for test_funct in functions:
        with patch('api.controllers.rootcheck_controller.DistributedAPI.__init__', return_value=None) as mock_dapi:
            with patch('api.controllers.rootcheck_controller.DistributedAPI.distribute_function',
                       return_value=AsyncMock()) as mock_dfunc:
                with patch('api.controllers.rootcheck_controller.raise_if_exc', return_value={}) as mock_exc:
                    await test_funct
