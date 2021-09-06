import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from aiohttp import web_response
from connexion.lifecycle import ConnexionResponse

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        with patch('api.configuration.api_conf'):
            sys.modules['wazuh.rbac.orm'] = MagicMock()
            import wazuh.rbac.decorators
            del sys.modules['wazuh.rbac.orm']

            from api.controllers.rule_controller import (get_rules,
                                                         get_rules_groups,
                                                         get_rules_requirement,
                                                         get_rules_files,
                                                         get_file,
                                                         put_file,
                                                         delete_file)
            from wazuh import rule as rule_framework
            from wazuh.tests.util import RBAC_bypasser

            wazuh.rbac.decorators.expose_resources = RBAC_bypasser


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', [MagicMock()])
@pytest.mark.parametrize('mock_bool', [(True), (False)])
async def test_rule_controller(mock_request, mock_bool):
    async def test_get_rules():
        calls = [call(f=rule_framework.get_rules,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_rules(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_rules_groups():
        calls = [call(f=rule_framework.get_groups,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_rules_groups(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_rules_requirement():
        calls = [call(f=rule_framework.get_requirement,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_rules_requirement(mock_request,
                                             requirement='-')
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_rules_files():
        calls = [call(f=rule_framework.get_rules_files,
                      f_kwargs=ANY,
                      request_type='local_any',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_rules_files(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_file(mock_bool):
        with patch('api.controllers.rule_controller.isinstance', return_value=mock_bool) as mock_isinstance:
            calls = [call(f=rule_framework.get_rule_file,
                          f_kwargs=ANY,
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=False,
                          logger=ANY,
                          rbac_permissions=mock_request['token_info']['rbac_policies']
                          )
                     ]
            result = await get_file(mock_request)
            mock_dapi.assert_has_calls(calls)
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            if mock_isinstance.return_value:
                assert isinstance(result, web_response.Response)
            else:
                assert isinstance(result, ConnexionResponse)

    async def test_put_file():
        with patch('api.controllers.rule_controller.Body.validate_content_type'):
            with patch('api.controllers.rule_controller.Body.decode_body', return_value={}):
                calls = [call(f=rule_framework.upload_rule_file,
                              f_kwargs=ANY,
                              request_type='local_master',
                              is_async=False,
                              wait_for_complete=False,
                              logger=ANY,
                              rbac_permissions=mock_request['token_info']['rbac_policies']
                              )
                         ]
                result = await put_file(mock_request,
                                        body={})
                mock_dapi.assert_has_calls(calls)
                mock_exc.assert_called_once_with(mock_dfunc.return_value)
                assert isinstance(result, web_response.Response)

    async def test_delete_file():
        calls = [call(f=rule_framework.delete_rule_file,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await delete_file(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    mock_request.request = {'aux', 'value2'}
    aux_d = {'token_info': {'rbac_policies': 'value1'}}
    mock_request.__getitem__.side_effect = aux_d.__getitem__
    functions = [test_get_rules(),
                 test_get_rules_groups(),
                 test_get_rules_requirement(),
                 test_get_rules_files(),
                 test_get_file(mock_bool),
                 test_put_file(),
                 test_delete_file()
                 ]
    for test_funct in functions:
        with patch('api.controllers.rule_controller.DistributedAPI.__init__', return_value=None) as mock_dapi:
            with patch('api.controllers.rule_controller.DistributedAPI.distribute_function',
                       return_value=AsyncMock()) as mock_dfunc:
                with patch('api.controllers.rule_controller.raise_if_exc',
                           return_value={'message': 'value1'}) as mock_exc:
                    await test_funct
