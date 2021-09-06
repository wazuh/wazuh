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
                                                      get_techniques)
        from wazuh import mitre
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', [{'token_info': {'rbac_policies': 'value1'}}])
async def test_mitre_controller(mock_request):
    async def test_get_metadata():
        calls = [call(f=mitre.mitre_metadata,
                      f_kwargs={},
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_metadata(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_groups():
        calls = [call(f=mitre.mitre_groups,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_groups(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_mitigations():
        calls = [call(f=mitre.mitre_mitigations,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_mitigations(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_references():
        calls = [call(f=mitre.mitre_references,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_references(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_software():
        calls = [call(f=mitre.mitre_software,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_software(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_tactics():
        calls = [call(f=mitre.mitre_tactics,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_tactics(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_techniques():
        calls = [call(f=mitre.mitre_techniques,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_techniques(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
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
        with patch('api.controllers.mitre_controller.DistributedAPI.__init__', return_value=None) as mock_dapi:
            with patch('api.controllers.mitre_controller.DistributedAPI.distribute_function',
                       return_value=AsyncMock()) as mock_dfunc:
                with patch('api.controllers.mitre_controller.raise_if_exc', return_value={}) as mock_exc:
                    await test_funct
