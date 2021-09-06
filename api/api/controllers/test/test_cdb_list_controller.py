import sys
from unittest.mock import ANY, AsyncMock, MagicMock, call, patch

import pytest
from aiohttp import web_response
from connexion.lifecycle import ConnexionResponse

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']

        from api.controllers.cdb_list_controller import (get_lists,
                                                         get_file,
                                                         put_file,
                                                         delete_file,
                                                         get_lists_files)
        from wazuh import cdb_list
        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser


@pytest.mark.asyncio
@pytest.mark.parametrize('mock_request', [{'token_info': {'rbac_policies': 'value1'}}])
@pytest.mark.parametrize('mock_bool', [(True), (False)])
async def test_cdb_list_controller(mock_request, mock_bool):
    async def test_get_lists():
        calls = [call(f=cdb_list.get_lists,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_lists(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    async def test_get_file(mock_bool):
        with patch('api.controllers.cdb_list_controller.isinstance', return_value=mock_bool) as mock_isinstance:
            calls = [call(f=cdb_list.get_list_file,
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
        with patch('api.controllers.cdb_list_controller.Body.validate_content_type'):
            with patch('api.controllers.cdb_list_controller.Body.decode_body', return_value={}):
                calls = [call(f=cdb_list.upload_list_file,
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
        calls = [call(f=cdb_list.delete_list_file,
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

    async def test_get_lists_files():
        calls = [call(f=cdb_list.get_path_lists,
                      f_kwargs=ANY,
                      request_type='local_master',
                      is_async=False,
                      wait_for_complete=False,
                      logger=ANY,
                      rbac_permissions=mock_request['token_info']['rbac_policies']
                      )
                 ]
        result = await get_lists_files(mock_request)
        mock_dapi.assert_has_calls(calls)
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        assert isinstance(result, web_response.Response)

    functions = [test_get_lists(),
                 test_get_file(mock_bool),
                 test_put_file(),
                 test_delete_file(),
                 test_get_lists_files()
                 ]
    for test_funct in functions:
        with patch('api.controllers.cdb_list_controller.DistributedAPI.__init__', return_value=None) as mock_dapi:
            with patch('api.controllers.cdb_list_controller.DistributedAPI.distribute_function',
                       return_value=AsyncMock()) as mock_dfunc:
                with patch('api.controllers.cdb_list_controller.raise_if_exc',
                           return_value={'message': 'value1'}) as mock_exc:
                    await test_funct
