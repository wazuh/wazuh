# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine

from framework.wazuh.rbac.tests.utils import init_db

test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data/')


@pytest.fixture(scope='function')
def db_setup():
    with patch('wazuh.core.common.wazuh_uid'), patch('wazuh.core.common.wazuh_gid'):
        with patch('sqlalchemy.create_engine', return_value=create_engine("sqlite://")):
            with patch('shutil.chown'), patch('os.chmod'):
                with patch('api.constants.SECURITY_PATH', new=test_data_path):
                    from wazuh.rbac.preprocessor import PreProcessor
    init_db('schema_security_test.sql', test_data_path)

    yield PreProcessor


permissions = list()
results = list()
actual_test = 0
with open(test_data_path + 'RBAC_preprocessor_policies.json') as f:
    file = json.load(f)

inputs = [test_case['no_processed_policies'] for test_case in file]
outputs = [test_case['processed_policies'] for test_case in file]


@pytest.mark.parametrize('input_, output', zip(inputs, outputs))
def test_expose_resources(db_setup, input_, output):
    preprocessor = db_setup()
    for policy in input_:
        preprocessor.process_policy(policy)
    preprocessed_policies = preprocessor.get_optimize_dict()
    assert preprocessed_policies == output


@pytest.fixture(scope='function')
def preprocessor_module():
    """Import the preprocessor module with the security DB stubbed out."""
    with patch('wazuh.core.common.wazuh_uid'), patch('wazuh.core.common.wazuh_gid'):
        with patch('sqlalchemy.create_engine', return_value=create_engine("sqlite://")):
            with patch('shutil.chown'), patch('os.chmod'):
                with patch('api.constants.SECURITY_PATH', new=test_data_path):
                    import wazuh.rbac.preprocessor as preprocessor

    yield preprocessor


@pytest.fixture(scope='function')
def rbac_mocks(preprocessor_module):
    """Patch `AuthenticationManager` and `RBAChecker` and yield both mocks."""
    with patch.object(preprocessor_module, 'AuthenticationManager') as auth_manager_class, \
            patch.object(preprocessor_module, 'RBAChecker') as rbac_checker_class:
        auth_manager = auth_manager_class.return_value.__enter__.return_value
        auth_manager.get_user.return_value = {'id': 1}
        yield auth_manager, rbac_checker_class.return_value


@pytest.mark.parametrize('auth_context', [
    {},
    {'user_name': 'wazuh-admin'},
])
def test_get_roles_uses_auth_context_method(preprocessor_module, rbac_mocks, auth_context):
    """Check that any given authorization context, empty included, is resolved through the checker.

    An empty context is falsy but present: it must go through the rules like any other context,
    never fall back to the account's static roles.
    """
    _, rbac_checker = rbac_mocks
    rbac_checker.run_auth_context_roles.return_value = []

    roles = preprocessor_module.get_roles(auth_context=auth_context, user_id='wazuh-wui')

    rbac_checker.run_auth_context_roles.assert_called_once_with()
    rbac_checker.run_user_role_link_roles.assert_not_called()
    assert roles == []


def test_get_roles_without_auth_context_uses_user_role_link(preprocessor_module, rbac_mocks):
    """Check that an absent authorization context falls back to the user-role link."""
    _, rbac_checker = rbac_mocks
    rbac_checker.run_user_role_link_roles.return_value = [1]

    roles = preprocessor_module.get_roles(auth_context=None, user_id='wazuh-wui')

    rbac_checker.run_user_role_link_roles.assert_called_once_with(1)
    rbac_checker.run_auth_context_roles.assert_not_called()
    assert roles == [1]


@pytest.mark.parametrize('auth_context', [
    {},
    {'user_name': 'wazuh-admin'},
])
def test_get_permissions_run_as_not_allowed(preprocessor_module, rbac_mocks, auth_context):
    """Check that a user without `allow_run_as` is denied for any given authorization context."""
    from wazuh.core.exception import WazuhPermissionError

    auth_manager, _ = rbac_mocks
    auth_manager.user_allow_run_as.return_value = False

    with pytest.raises(WazuhPermissionError, match='.* 6004 .*'):
        preprocessor_module.get_permissions(user_id='wazuh-wui', auth_context=auth_context)


def test_get_permissions_empty_auth_context_returns_no_roles(preprocessor_module, rbac_mocks):
    """Check that an empty authorization context is resolved through the rules, not the user link."""
    auth_manager, rbac_checker = rbac_mocks
    auth_manager.user_allow_run_as.return_value = True
    rbac_checker.run_auth_context_roles.return_value = []

    result = preprocessor_module.get_permissions(user_id='wazuh-wui', auth_context={})

    rbac_checker.run_auth_context_roles.assert_called_once_with()
    rbac_checker.run_user_role_link_roles.assert_not_called()
    assert result.dikt == {'roles': []}


def test_get_permissions_without_auth_context_returns_static_roles(preprocessor_module, rbac_mocks):
    """Check that the plain login path still returns the account's static roles."""
    auth_manager, rbac_checker = rbac_mocks
    auth_manager.user_allow_run_as.return_value = False
    rbac_checker.run_user_role_link_roles.return_value = [1]

    result = preprocessor_module.get_permissions(user_id='wazuh-wui', auth_context=None)

    rbac_checker.run_user_role_link_roles.assert_called_once_with(1)
    rbac_checker.run_auth_context_roles.assert_not_called()
    assert result.dikt == {'roles': [1]}
