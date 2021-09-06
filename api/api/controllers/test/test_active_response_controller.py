import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from aiohttp import web_response

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']

        from api.controllers.active_response_controller import run_command
        from wazuh import active_response
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', [{'token_info': {'rbac_policies': 'value1'}}])
async def test_get_vulnerability_agent(mock_request):
    with patch('api.controllers.active_response_controller.DistributedAPI.__init__', return_value=None) as mock_dapi:
        with patch('api.controllers.active_response_controller.DistributedAPI.distribute_function',
                   return_value=AsyncMock()) as mock_dfunc:
            with patch('api.controllers.active_response_controller.raise_if_exc', return_value={}) as mock_exc:
                with patch('api.controllers.active_response_controller.Body'):
                    with patch('api.controllers.active_response_controller.ActiveResponseModel.get_kwargs',
                               side_effect=AsyncMock, return_value={}):
                        calls = [call(f=active_response.run_command,
                                      f_kwargs=ANY,
                                      request_type='distributed_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      broadcasting=True,
                                      rbac_permissions=mock_request['token_info']['rbac_policies']
                                      )
                                 ]
                        result = await run_command(mock_request)
                        mock_dapi.assert_has_calls(calls)
                        mock_exc.assert_called_once_with(mock_dfunc.return_value)
                        assert isinstance(result, web_response.Response)
