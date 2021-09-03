import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from aiohttp import web_response

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']

        from api.controllers.active_response_controller import (run_command,
                                                                remove_nones_to_dict)
        from wazuh import active_response
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_str_value, mock_bool_value, mock_request',
                         [(ANY, True, {'token_info': {'rbac_policies': 'value1'}}),
                          (ANY, True, {'token_info': {'rbac_policies': 'value1'}}),
                          (ANY, False, {'token_info': {'rbac_policies': 'value1'}}),
                          (ANY, False, {'token_info': {'rbac_policies': 'value1'}})])
async def test_get_vulnerability_agent(mock_str_value,
                                       mock_bool_value,
                                       mock_request):
    with patch('api.controllers.active_response_controller.DistributedAPI', side_effect=AsyncMock) as mock_dapi:
        with patch('api.controllers.active_response_controller.raise_if_exc', return_value={}) as mock_exc:
            with patch('api.controllers.active_response_controller.Body'):
                with patch('api.controllers.active_response_controller.ActiveResponseModel.get_kwargs',
                           side_effect=AsyncMock, return_value={}):
                    calls = [call(f=active_response.run_command,
                                  f_kwargs=remove_nones_to_dict({}),
                                  request_type='distributed_master',
                                  is_async=False,
                                  wait_for_complete=mock_bool_value,
                                  logger=mock_str_value,
                                  broadcasting=True,
                                  rbac_permissions=mock_request['token_info']['rbac_policies']
                                  )
                             ]
                    result = await run_command(mock_request,
                                               agents_list='*',
                                               pretty=mock_bool_value,
                                               wait_for_complete=mock_bool_value
                                               )
                    mock_dapi.assert_has_calls(calls)
                    mock_exc.assert_called_once()
                    assert isinstance(result, web_response.Response)
