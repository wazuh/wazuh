import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from aiohttp import web_response

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']

        from api.controllers.ciscat_controller import get_agents_ciscat_results
        import wazuh.ciscat as ciscat
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', [MagicMock()])
async def test_get_vulnerability_agent(mock_request):
    mock_request.request = {'pass', 'value2'}
    aux_d = {'token_info': {'rbac_policies': 'value1'}}
    mock_request.__getitem__.side_effect = aux_d.__getitem__
    with patch('api.controllers.ciscat_controller.DistributedAPI.__init__', return_value=None) as mock_dapi:
        with patch('api.controllers.ciscat_controller.DistributedAPI.distribute_function',
                   return_value=AsyncMock()) as mock_dfunc:
            with patch('api.controllers.ciscat_controller.raise_if_exc', return_value={}) as mock_exc:
                calls = [call(f=ciscat.get_ciscat_results,
                              f_kwargs=ANY,
                              request_type='distributed_master',
                              is_async=False,
                              wait_for_complete=False,
                              logger=ANY,
                              rbac_permissions=mock_request['token_info']['rbac_policies']
                              )
                         ]
                result = await get_agents_ciscat_results(mock_request,
                                                         agent_id='001')
                mock_dapi.assert_has_calls(calls)
                mock_exc.assert_called_once_with(mock_dfunc.return_value)
                assert isinstance(result, web_response.Response)
