import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from aiohttp import web_response

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from api.controllers.sca_controller import (get_sca_agent,
                                                    get_sca_checks)
        from wazuh import sca
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', [{'token_info': {'rbac_policies': 'rbac_policies_value'}}])
async def test_sca_controller(mock_request):
    async def test_get_sca_agent():
        calls = [call(f=sca.get_sca_list,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_sca_agent(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_sca_checks():
        calls = [call(f=sca.get_sca_checks,
                      f_kwargs=ANY,
                      request_type='distributed_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_sca_checks(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    functions = [test_get_sca_agent(),
                 test_get_sca_checks()
                 ]
    for test_funct in functions:
        with patch('api.controllers.sca_controller.DistributedAPI.__init__', return_value=None) as mock_dapi:
            with patch('api.controllers.sca_controller.DistributedAPI.distribute_function',
                       return_value=AsyncMock()) as mock_dfunc:
                with patch('api.controllers.sca_controller.raise_if_exc', return_value={}) as mock_exc:
                    await test_funct
