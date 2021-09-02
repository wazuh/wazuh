import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from aiohttp import web_response

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']

        from api.controllers.task_controller import (get_tasks_status,
                                                     parse_api_param,
                                                     remove_nones_to_dict)
        from wazuh import task
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_str_value, mock_bool_value, mock_offset_value, mock_limit, mock_request',
                         [(ANY, True, 0, 20, {'token_info': {'rbac_policies': 'value1'}}),
                          (ANY, True, 1, 500, {'token_info': {'rbac_policies': 'value1'}}),
                          (ANY, False, 0, 1, {'token_info': {'rbac_policies': 'value1'}}),
                          (ANY, False, 10, 1, {'token_info': {'rbac_policies': 'value1'}})])
async def test_get_vulnerability_agent(
                                       mock_str_value,
                                       mock_bool_value,
                                       mock_offset_value,
                                       mock_limit,
                                       mock_request):
    with patch('api.controllers.task_controller.DistributedAPI', side_effect=AsyncMock) as mock_dapi:
        with patch('api.controllers.task_controller.raise_if_exc', return_value={}) as mock_exc:
            f_kwargs = {'select': mock_str_value,
                        'search': parse_api_param(None, 'search'),
                        'offset': mock_offset_value,
                        'limit': mock_limit,
                        'filters': {
                            'task_list': mock_str_value,
                            'agent_list': mock_str_value,
                            'status': mock_str_value,
                            'module': mock_str_value,
                            'command': mock_str_value,
                            'node': mock_str_value
                        },
                        'sort': parse_api_param(None, 'sort'),
                        'q': None
                        }
            calls = [call(f=task.get_task_status,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=mock_bool_value,
                          logger=mock_str_value,
                          rbac_permissions=mock_request['token_info']['rbac_policies']
                          )
                     ]
            result = await get_tasks_status(mock_request,
                                            pretty=mock_bool_value,
                                            wait_for_complete=mock_bool_value,
                                            offset=mock_offset_value,
                                            limit=mock_limit,
                                            tasks_list=mock_str_value,
                                            agents_list=mock_str_value,
                                            command=mock_str_value,
                                            node=mock_str_value,
                                            module=mock_str_value,
                                            status=mock_str_value,
                                            select=mock_str_value)
            mock_dapi.assert_has_calls(calls)
            mock_exc.assert_called_once()
            assert isinstance(result, web_response.Response)
