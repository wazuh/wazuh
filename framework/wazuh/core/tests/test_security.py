# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from contextvars import ContextVar
from unittest.mock import patch

import pytest
from wazuh.tests.test_security import db_setup  # noqa


@patch('yaml.safe_load')
def test_load_spec(mock_safe_load, db_setup):
    """Test if the function load_spec works properly.

    Parameters
    ----------
    mock_safe_load: MagicMock
        Mock of safe_load method.
    db_setup: callable
        This function creates the rbac.db file.
    """
    security, _, _ = db_setup
    # To execute the function first it's necessary to clear the cache.
    security.load_spec.cache_clear()
    security.load_spec()
    mock_safe_load.assert_called()
    # Clearing the cache again since this call used mocked resources.
    security.load_spec.cache_clear()


def test_revoke_tokens(db_setup):
    """Checks that the return value of revoke_tokens is a WazuhResult.

    Parameters
    ----------
    db_setup: callable
        This function creates the rbac.db file.
    """
    security, WazuhResult, _ = db_setup
    mock_current_user = ContextVar('current_user', default='wazuh')
    with patch('wazuh.core.common.current_user', new=mock_current_user):
        result = security.revoke_current_user_tokens()
        assert isinstance(result, WazuhResult)


@pytest.mark.parametrize('role_list, expected_roles', [([104], {104}), ([102, 103], {102, 103}), ([], set())])
def test_invalid_roles_tokens(db_setup, role_list, expected_roles):
    """Check that the argument passed to `TokenManager.add_user_roles_rules` formed by `roles` is correct.

    Parameters
    ----------
    db_setup: callable
        This function creates the rbac.db file.
    role_list : list
        List of roles.
    expected_roles : set
        Expected roles.
    """
    with patch('wazuh.core.security.TokenManager.add_user_roles_rules') as TM_mock:
        _, _, core_security = db_setup
        core_security.invalid_roles_tokens(roles=[role_id for role_id in role_list])
        assert set(TM_mock.call_args.kwargs['roles']) == expected_roles


@patch('wazuh.core.security.TokenManager.add_user_roles_rules')
def test_invalid_run_as_tokens(mock_add_user_roles_rules, db_setup):
    """Check that TokenManager's add_user_roles_rules method is called with the expected parameters.

    Parameters
    ----------
    db_setup: callable
        This function creates the rbac.db file.
    """
    _, _, core_security = db_setup
    core_security.invalid_run_as_tokens()
    mock_add_user_roles_rules.assert_called_with(run_as=True)


@pytest.mark.parametrize(
    'role_list, expected_users', [([100, 101], {100, 103, 102}), ([102], {104}), ([102, 103, 104], {101, 104, 102})]
)
def test_check_relationships(db_setup, role_list, expected_users):
    """Check that the relationship between role and user is correct according to
    `schema_security_test.sql`.

    Parameters
    ----------
    db_setup: callable
        This function creates the rbac.db file.
    role_list : list
        List of role IDs.
    expected_users : set
        Expected users.
    """
    _, _, core_security = db_setup
    assert core_security.check_relationships(roles=[role_id for role_id in role_list]) == expected_users


@pytest.mark.parametrize('user_list, expected_users', [([104], {104}), ([102, 103], {102, 103}), ([], set())])
def test_invalid_users_tokens(db_setup, user_list, expected_users):
    """Check that the argument passed to `TokenManager.add_user_roles_rules` formed by `users` is correct.

    Parameters
    ----------
    db_setup: callable
        This function creates the rbac.db file.
    user_list : list
        List of users.
    expected_users : set
        Expected users.
    """
    with patch('wazuh.core.security.TokenManager.add_user_roles_rules') as TM_mock:
        _, _, core_security = db_setup
        core_security.invalid_users_tokens(users=[user_id for user_id in user_list])
        related_users = TM_mock.call_args.kwargs['users']
        assert set(related_users) == expected_users


@patch('wazuh.core.security.revoke_tokens')
@patch('wazuh.core.security.check_database_integrity')
@patch('wazuh.core.security.os.remove')
def test_rbac_db_factory_reset(remove_mock, db_integrity_mock, revoke_mock, db_setup):
    """Check that the RBAC database factory reset is correct."""
    _, _, core_security = db_setup
    assert core_security.rbac_db_factory_reset() == {'reset': True}
    assert remove_mock.call_args[0][0].name == 'rbac.db'
    db_integrity_mock.assert_called_once()
    revoke_mock.assert_called_once()
