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
        with patch('api.configuration.api_conf'):
            sys.modules['wazuh.rbac.orm'] = MagicMock()
            import wazuh.rbac.decorators
            from api.controllers.rule_controller import (delete_file, get_file,
                                                         get_rules,
                                                         get_rules_files,
                                                         get_rules_groups,
                                                         get_rules_requirement,
                                                         put_file)
            from wazuh import rule as rule_framework
            from wazuh.tests.util import RBAC_bypasser
            wazuh.rbac.decorators.expose_resources = RBAC_bypasser
            del sys.modules['wazuh.rbac.orm']


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["rule_controller"], indirect=True)
@patch('api.controllers.rule_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.rule_controller.remove_nones_to_dict')
@patch('api.controllers.rule_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.rule_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_rules(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_rules' endpoint is working as expected."""
    result = await get_rules()
    f_kwargs = {'rule_ids': None,
                'offset': 0,
                'limit': None,
                'select': None,
                'sort_by': ['id'],
                'sort_ascending': True,
                'search_text': None,
                'complementary_search': None,
                'q': None,
                'status': None,
                'group': None,
                'level': None,
                'filename': None,
                'relative_dirname': None,
                'pci_dss': None,
                'gdpr': None,
                'gpg13': None,
                'hipaa': None,
                'nist_800_53': mock_request.query_params.get('nist-800-53', None),
                'tsc': None,
                'mitre': None,
                'distinct': False
                }
    mock_dapi.assert_called_once_with(f=rule_framework.get_rules,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["rule_controller"], indirect=True)
@patch('api.controllers.rule_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.rule_controller.remove_nones_to_dict')
@patch('api.controllers.rule_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.rule_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_rules_groups(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_rules_groups' endpoint is working as expected."""
    result = await get_rules_groups()
    f_kwargs = {'offset': 0,
                'limit': None,
                'sort_by': [''],
                'sort_ascending': True,
                'search_text': None,
                'complementary_search': None
                }
    mock_dapi.assert_called_once_with(f=rule_framework.get_groups,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["rule_controller"], indirect=True)
@patch('api.controllers.rule_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.rule_controller.remove_nones_to_dict')
@patch('api.controllers.rule_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.rule_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_rules_requirement(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_rules_requirement' endpoint is working as expected."""
    result = await get_rules_requirement(
                                         requirement='-')
    f_kwargs = {'requirement': '_',
                'sort_by': [''],
                'sort_ascending': True,
                'search_text': None,
                'complementary_search': None,
                'offset': 0,
                'limit': None
                }
    mock_dapi.assert_called_once_with(f=rule_framework.get_requirement,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["rule_controller"], indirect=True)
@patch('api.controllers.rule_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.rule_controller.remove_nones_to_dict')
@patch('api.controllers.rule_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.rule_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_get_rules_files(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'get_rules_files' endpoint is working as expected."""
    result = await get_rules_files()
    f_kwargs = {'offset': 0,
                'limit': None,
                'sort_by': ['filename'],
                'sort_ascending': True,
                'search_text': None,
                'complementary_search': None,
                'status': None,
                'filename': None,
                'relative_dirname': None,
                'q': None,
                'select': None,
                'distinct': False
                }
    mock_dapi.assert_called_once_with(f=rule_framework.get_rules_files,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='local_any',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies']
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["rule_controller"], indirect=True)
@patch('api.controllers.rule_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.rule_controller.remove_nones_to_dict')
@patch('api.controllers.rule_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.rule_controller.raise_if_exc', return_value=CustomAffectedItems())
@pytest.mark.parametrize('mock_bool', [True, False])
async def test_get_file(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_bool, mock_request):
    """Verify 'get_file' endpoint is working as expected."""
    with patch('api.controllers.rule_controller.isinstance', return_value=mock_bool) as mock_isinstance:
        result = await get_file()
        f_kwargs = {'filename': None,
                    'raw': False,
                    'relative_dirname': None
                    }
        mock_dapi.assert_called_once_with(f=rule_framework.get_rule_file,
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
@pytest.mark.parametrize("mock_request", ["rule_controller"], indirect=True)
@patch('api.controllers.rule_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.rule_controller.remove_nones_to_dict')
@patch('api.controllers.rule_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.rule_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_put_file(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'put_file' endpoint is working as expected."""
    with patch('api.controllers.rule_controller.Body.validate_content_type'):
        with patch('api.controllers.rule_controller.Body.decode_body') as mock_dbody:
            result = await put_file(
                                    body={})
            f_kwargs = {'filename': None,
                        'overwrite': False,
                        'relative_dirname': None,
                        'content': mock_dbody.return_value
                        }
            mock_dapi.assert_called_once_with(f=rule_framework.upload_rule_file,
                                              f_kwargs=mock_remove.return_value,
                                              request_type='distributed_master',
                                              is_async=False,
                                              wait_for_complete=False,
                                              logger=ANY,
                                              rbac_permissions=mock_request.context['token_info']['rbac_policies'],
                                              broadcasting=True,
                                              nodes=None
                                              )
            mock_exc.assert_called_once_with(mock_dfunc.return_value)
            mock_remove.assert_called_once_with(f_kwargs)
            assert isinstance(result, ConnexionResponse)


@pytest.mark.asyncio
@pytest.mark.parametrize("mock_request", ["rule_controller"], indirect=True)
@patch('api.controllers.rule_controller.DistributedAPI.distribute_function', return_value=AsyncMock())
@patch('api.controllers.rule_controller.remove_nones_to_dict')
@patch('api.controllers.rule_controller.DistributedAPI.__init__', return_value=None)
@patch('api.controllers.rule_controller.raise_if_exc', return_value=CustomAffectedItems())
async def test_delete_file(mock_exc, mock_dapi, mock_remove, mock_dfunc, mock_request):
    """Verify 'delete_file' endpoint is working as expected."""
    result = await delete_file()
    f_kwargs = {'filename': None, 
                'relative_dirname': None}
    
    mock_dapi.assert_called_once_with(f=rule_framework.delete_rule_file,
                                      f_kwargs=mock_remove.return_value,
                                      request_type='distributed_master',
                                      is_async=False,
                                      wait_for_complete=False,
                                      logger=ANY,
                                      rbac_permissions=mock_request.context['token_info']['rbac_policies'],
                                      broadcasting=True,
                                      nodes=None
                                      )
    mock_exc.assert_called_once_with(mock_dfunc.return_value)
    mock_remove.assert_called_once_with(f_kwargs)
    assert isinstance(result, ConnexionResponse)
