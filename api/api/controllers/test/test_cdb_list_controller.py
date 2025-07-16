# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest
from connexion.lifecycle import ConnexionResponse
from api.controllers.test.utils import CustomAffectedItems

with patch('wazuh.common.wazuh_uid'):
    with patch('wazuh.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators
        from api.controllers.cdb_list_controller import (delete_file, get_file,
                                                         get_lists,
                                                         get_lists_files,
                                                         put_file)
        from wazuh import cdb_list
        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["cdb_list_controller"], indirect=True)
@patch('api.controllers.cdb_list_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cdb_list_controller.remove_nones_to_dict')
@patch('api.controllers.cdb_list_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cdb_list_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_lists(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_lists' endpoint is working as expected."""
    result = await get_lists()
    f_kwargs = {'offset': 0,
                'select': None,
                'limit': None,
                'sort_by': ['relative_dirname', 'filename'],
                'sort_ascending': True,
                'search_text': None,
                'complementary_search': None,
                'filename': None,
                'relative_dirname': None,
                'q': None,
                'distinct': False
                }
    mock_dapi.assert_called_once_with(f=cdb_list.get_lists,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["cdb_list_controller"], indirect=True)
@patch('api.controllers.cdb_list_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cdb_list_controller.remove_nones_to_dict')
@patch('api.controllers.cdb_list_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cdb_list_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_bool', [True, False])
async def test_get_file(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_bool, mock_request):
    """Verify 'get_file' endpoint is working as expected."""
    with patch('api.controllers.cdb_list_controller.isinstance', return_value=mock_bool) as mock_isinstance:
        result = await get_file()
        f_kwargs = {'filename': None,
                    'raw': False
                    }
        mock_dapi.assert_called_once_with(f=cdb_list.get_list_file,
                                          f_kwargs=mock_remove.return_value,
                                          request_type='local_master',
                                          is_async=False,
                                          wait_for_complete=False,
                                          logger=ANY,
                                          rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                          )
        mock_exc.assert_called_once_with(mock_dfunc.return_value)
        mock_remove.assert_called_once_with(f_kwargs)
        if mock_isinstance.return_value:
            assert isinstance(result, ConnexionResponse)
        else:
            assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["cdb_list_controller"], indirect=True)
@patch('api.controllers.cdb_list_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cdb_list_controller.remove_nones_to_dict')
@patch('api.controllers.cdb_list_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cdb_list_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_put_file(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'put_file' endpoint is working as expected."""
    with patch('api.controllers.cdb_list_controller.Body.validate_content_type'):
        with patch('api.controllers.cdb_list_controller.Body.decode_body') as mock_dbody:
            result = await put_file(
                                    body={})
            f_kwargs = {'filename': None,
                        'overwrite': False,
                        'content': mock_dbody.return_value
                        }
            mock_dapi.assert_called_once_with(f=cdb_list.upload_list_file,
                                              f_kwargs=mock_remove.return_value,
                                              request_type='distributed_master',
                                              is_async=False,
                                              wait_for_complete=False,
                                              logger=ANY,
                                              rbac_permissions=mock_request.context['token_info']['rbac_policies'],
                                              broadcasting=True
                                              )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(f_kwargs)
            assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["cdb_list_controller"], indirect=True)
@patch('api.controllers.cdb_list_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cdb_list_controller.remove_nones_to_dict')
@patch('api.controllers.cdb_list_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cdb_list_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_delete_file(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'delete_file' endpoint is working as expected."""
    result = await delete_file()
    f_kwargs = {'filename': None
                }
    mock_dapi.assert_called_once_with(f=cdb_list.delete_list_file,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies'],
                                      broadcasting=True
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["cdb_list_controller"], indirect=True)
@patch('api.controllers.cdb_list_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.cdb_list_controller.remove_nones_to_dict')
@patch('api.controllers.cdb_list_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.cdb_list_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_lists_files(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_lists_files' endpoint is working as expected."""
    result = await get_lists_files()
    f_kwargs = {'offset': 0,
                'limit': None,
                'sort_by': ['relative_dirname', 'filename'],
                'sort_ascending': True,
                'search_text': None,
                'complementary_search': None,
                'search_in_fields': ['filename', 'relative_dirname'],
                'filename': None,
                'relative_dirname': None,
                }
    mock_dapi.assert_called_once_with(f=cdb_list.get_path_lists,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)
