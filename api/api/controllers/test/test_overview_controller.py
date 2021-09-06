import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from aiohttp import web_response

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']

        from api.controllers.overview_controller import get_overview_agents
        from wazuh.agent import get_full_overview
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', [{'token_info': {'rbac_policies': 'value1'}}])
async def test_get_overview_agents(mock_request):
    with patch('api.controllers.overview_controller.DistributedAPI.__init__', return_value=None) as mock_dapi:
        with patch('api.controllers.overview_controller.DistributedAPI.distribute_function',
                   return_value=AsyncMock()) as mock_dfunc:
            with patch('api.controllers.overview_controller.raise_if_exc', return_value={}) as mock_exc:
                calls = [call(f=get_full_overview,
                              f_kwargs=ANY,
                              request_type='local_master',
                              is_async=False,
                              wait_for_complete=False,
                              logger=ANY,
                              rbac_permissions=mock_request['token_info']['rbac_policies']
                              )
                         ]
                result = await get_overview_agents(mock_request)
                mock_dapi.assert_has_calls(calls)
                mock_exc.assert_called_once_with(mock_dfunc.return_value)
                assert isinstance(result, web_response.Response)
