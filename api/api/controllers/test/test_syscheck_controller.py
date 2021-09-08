import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from aiohttp import web_response

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from api.controllers.syscheck_controller import (put_syscheck,
                                                         get_syscheck_agent,
                                                         delete_syscheck_agent,
                                                         get_last_scan_agent)
        from wazuh import syscheck
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser        
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', [MagicMock()])
async def test_syscheck_controller(mock_request):
    async def test_put_syscheck():
        calls = [call(f=syscheck.run,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      broadcasting=True,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await put_syscheck(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_syscheck_agent():
        calls = [call(f=syscheck.files,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_syscheck_agent(request=mock_request,
                                          agent_id='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_delete_syscheck_agent():
        calls = [call(f=syscheck.clear,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await delete_syscheck_agent(request=mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_last_scan_agent():
        calls = [call(f=syscheck.last_scan,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_last_scan_agent(request=mock_request,
                                           agent_id='001')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    mock_request.request = {'aux', 'aux_value'}
    aux_d = {'token_info': {'rbac_policies': 'rbac_policies_value'}}
    mock_request.__getitem__.side_effect = aux_d.__getitem__
    functions = [test_put_syscheck(),
                 test_get_syscheck_agent(),
                 test_delete_syscheck_agent(),
                 test_get_last_scan_agent()
                 ]
    for test_funct in functions:
        with patch('api.controllers.syscheck_controller.DistributedAPI.__init__', return_value=None) as mock_dapi:
            with patch('api.controllers.syscheck_controller.DistributedAPI.distribute_function',
                       return_value=AsyncMock()) as mock_dfunc:
                with patch('api.controllers.syscheck_controller.raise_if_exc', return_value={}) as mock_exc:
                    await test_funct
