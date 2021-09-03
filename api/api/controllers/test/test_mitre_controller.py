import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from aiohttp import web_response

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']

        from api.controllers.mitre_controller import (get_groups,
                                                      get_metadata,
                                                      get_mitigations,
                                                      get_references,
                                                      get_software,
                                                      get_tactics,
                                                      get_techniques,
                                                      remove_nones_to_dict)
        from wazuh import mitre
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_str_value, mock_bool_value, mock_offset_value, mock_limit, mock_request',
                         [(ANY, True, 0, 20, {'token_info': {'rbac_policies': 'value1'}}),
                          (ANY, True, 1, 500, {'token_info': {'rbac_policies': 'value1'}}),
                          (ANY, False, 0, 1, {'token_info': {'rbac_policies': 'value1'}}),
                          (ANY, False, 10, 1, {'token_info': {'rbac_policies': 'value1'}})])
async def test_mitre_controller(mock_str_value,
                                mock_bool_value,
                                mock_offset_value,
                                mock_limit,
                                mock_request):
    async def test_get_metadata():
        calls = [call(f=mitre.mitre_metadata,
                      f_kwargs={},
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=mock_bool_value,
                      logger=mock_str_value,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_metadata(mock_request,
                                    pretty=mock_bool_value,
                                    wait_for_complete=mock_bool_value
                                    )
        mock_exc.assert_called_once()
        mock_dapi.assert_has_calls(calls)
        assert isinstance(result, web_response.Response)

    async def test_get_groups():
        f_kwargs = {
            'filters': {
                'id': mock_str_value
                },
            'offset': mock_offset_value,
            'limit': mock_limit,
            'sort_by': None,
            'sort_ascending': False,
            'search_text': None,
            'complementary_search': None,
            'select': mock_str_value,
            'q': None
            }
        calls = [call(f=mitre.mitre_groups,
                      f_kwargs=remove_nones_to_dict(f_kwargs),
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=mock_bool_value,
                      logger=mock_str_value,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_groups(mock_request,
                                  group_ids=mock_str_value,
                                  pretty=mock_bool_value,
                                  wait_for_complete=mock_bool_value,
                                  offset=mock_offset_value,
                                  limit=mock_limit,
                                  select=mock_str_value
                                  )
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once()
        assert isinstance(result, web_response.Response)

    async def test_get_mitigations():
        f_kwargs = {
            'filters': {
                'id': mock_str_value
                },
            'offset': mock_offset_value,
            'limit': mock_limit,
            'sort_by': None,
            'sort_ascending': False,
            'search_text': None,
            'complementary_search': None,
            'select': mock_str_value,
            'q': None
            }
        calls = [call(f=mitre.mitre_mitigations,
                      f_kwargs=remove_nones_to_dict(f_kwargs),
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=mock_bool_value,
                      logger=mock_str_value,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_mitigations(mock_request,
                                       mitigation_ids=mock_str_value,
                                       pretty=mock_bool_value,
                                       wait_for_complete=mock_bool_value,
                                       offset=mock_offset_value,
                                       limit=mock_limit,
                                       select=mock_str_value
                                       )
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once()
        assert isinstance(result, web_response.Response)

    async def test_get_references():
        f_kwargs = {
            'filters': {
                'id': mock_str_value
                },
            'offset': mock_offset_value,
            'limit': mock_limit,
            'sort_by': None,
            'sort_ascending': False,
            'search_text': None,
            'complementary_search': None,
            'select': mock_str_value,
            'q': None
            }
        calls = [call(f=mitre.mitre_references,
                      f_kwargs=remove_nones_to_dict(f_kwargs),
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=mock_bool_value,
                      logger=mock_str_value,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_references(mock_request,
                                      reference_ids=mock_str_value,
                                      pretty=mock_bool_value,
                                      wait_for_complete=mock_bool_value,
                                      offset=mock_offset_value,
                                      limit=mock_limit,
                                      select=mock_str_value
                                      )
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once()
        assert isinstance(result, web_response.Response)

    async def test_get_software():
        f_kwargs = {
            'filters': {
                'id': mock_str_value
            },
            'offset': mock_offset_value,
            'limit': mock_limit,
            'sort_by': None,
            'sort_ascending': False,
            'search_text': None,
            'complementary_search': None,
            'select': mock_str_value,
            'q': None
        }
        calls = [call(f=mitre.mitre_software,
                      f_kwargs=remove_nones_to_dict(f_kwargs),
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=mock_bool_value,
                      logger=mock_str_value,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_software(mock_request,
                                    software_ids=mock_str_value,
                                    pretty=mock_bool_value,
                                    wait_for_complete=mock_bool_value,
                                    offset=mock_offset_value,
                                    limit=mock_limit,
                                    select=mock_str_value
                                    )
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once()
        assert isinstance(result, web_response.Response)

    async def test_get_tactics():
        f_kwargs = {
            'filters': {
                'id': mock_str_value,
                },
            'offset': mock_offset_value,
            'limit': mock_limit,
            'sort_by': None,
            'sort_ascending': False,
            'search_text': None,
            'complementary_search': None,
            'select': mock_str_value,
            'q': None
        }
        calls = [call(f=mitre.mitre_tactics,
                      f_kwargs=remove_nones_to_dict(f_kwargs),
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=mock_bool_value,
                      logger=mock_str_value,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_tactics(mock_request,
                                   tactic_ids=mock_str_value,
                                   pretty=mock_bool_value,
                                   wait_for_complete=mock_bool_value,
                                   offset=mock_offset_value,
                                   limit=mock_limit,
                                   select=mock_str_value
                                   )
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once()
        assert isinstance(result, web_response.Response)

    async def test_get_techniques():
        f_kwargs = {
            'filters': {
                'id': mock_str_value,
                },
            'offset': mock_offset_value,
            'limit': mock_limit,
            'sort_by': None,
            'sort_ascending': False,
            'search_text': None,
            'complementary_search': None,
            'select': mock_str_value,
            'q': None
            }
        calls = [call(f=mitre.mitre_techniques,
                      f_kwargs=remove_nones_to_dict(f_kwargs),
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=mock_bool_value,
                      logger=mock_str_value,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_techniques(mock_request,
                                      technique_ids=mock_str_value,
                                      pretty=mock_bool_value,
                                      wait_for_complete=mock_bool_value,
                                      offset=mock_offset_value,
                                      limit=mock_limit,
                                      select=mock_str_value
                                      )
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once()
        assert isinstance(result, web_response.Response)

    functions = [test_get_metadata(),
                 test_get_groups(),
                 test_get_mitigations(),
                 test_get_techniques(),
                 test_get_references(),
                 test_get_software(),
                 test_get_tactics()
                 ]
    for test_funct in functions:
        with patch('api.controllers.mitre_controller.DistributedAPI', side_effect=AsyncMock) as mock_dapi:
            with patch('api.controllers.mitre_controller.raise_if_exc', return_value={}) as mock_exc:
                await test_funct
