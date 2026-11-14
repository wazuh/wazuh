# Copyright (C) Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from contextvars import ContextVar
from unittest.mock import patch

import pytest
import yaml

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
    with patch('wazuh.core.security.change_keypair', side_effect=None):
        security, WazuhResult, _ = db_setup
        mock_current_user = ContextVar('current_user', default='wazuh')
        with patch("wazuh.core.common.current_user", new=mock_current_user):
            result = security.revoke_current_user_tokens()
            assert isinstance(result, WazuhResult)


@pytest.mark.parametrize('role_list, expected_roles', [
    ([104], {104}),
    ([102, 103], {102, 103}),
    ([], set())
])
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


@patch('wazuh.core.security.TokenManager.add_user_roles_rules')
def test_invalid_run_as_context_tokens(mock_add_user_roles_rules, db_setup):
    """Check that only the given run_as authorization contexts are handed to add_user_roles_rules."""
    _, _, core_security = db_setup
    core_security.invalid_run_as_context_tokens(contexts=['abc', 'abc', 'def'])
    mock_add_user_roles_rules.assert_called_with(contexts={'abc', 'def'})


def test_revoke_run_as_tokens_by_authorization_context(db_setup):
    """Logging out with a run_as token revokes its authorization context, never the account it names."""
    security, WazuhResult, _ = db_setup
    mock_current_user = ContextVar('current_user', default='wazuh-internal-client')
    with patch("wazuh.core.common.current_user", new=mock_current_user), \
            patch('wazuh.security.invalid_users_tokens') as mock_users, \
            patch('wazuh.security.invalid_run_as_context_tokens') as mock_contexts:
        result = security.revoke_current_user_tokens(run_as=True, hash_auth_context='abc')

    assert isinstance(result, WazuhResult)
    mock_contexts.assert_called_once_with(contexts=['abc'])
    mock_users.assert_not_called()


def test_revoke_non_run_as_tokens_by_user(db_setup):
    """Logging out with a regular token still revokes every token of its user."""
    security, _, _ = db_setup
    mock_current_user = ContextVar('current_user', default='wazuh')
    with patch("wazuh.core.common.current_user", new=mock_current_user), \
            patch('wazuh.security.invalid_users_tokens') as mock_users, \
            patch('wazuh.security.invalid_run_as_context_tokens') as mock_contexts:
        security.revoke_current_user_tokens()

    mock_users.assert_called_once()
    assert len(mock_users.call_args.kwargs['users']) == 1
    mock_contexts.assert_not_called()


@pytest.mark.parametrize('user_list, expected_users', [
    ([104], {104}),
    ([102, 103], {102, 103}),
    ([], set())
])
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


@patch("wazuh.core.security.revoke_tokens")
@patch("wazuh.core.security.check_database_integrity")
@patch("wazuh.core.security.os.remove")
def test_rbac_db_factory_reset(remove_mock, db_integrity_mock, revoke_mock, db_setup):
    """Check that the RBAC database factory reset is correct."""
    _, _, core_security = db_setup
    assert core_security.rbac_db_factory_reset() == {'reset': True}
    assert remove_mock.call_args[0][0].endswith("rbac.db")
    db_integrity_mock.assert_called_once()
    revoke_mock.assert_called_once()


@pytest.mark.parametrize('policy, expected', [
    ({'actions': ['agent:read'], 'resources': ['agent:id:*'], 'effect': 'allow'}, True),
    ({'actions': ['agent:read', 'group:read'], 'resources': ['agent:id:001', 'group:id:default'],
      'effect': 'deny'}, True),
    ({'actions': ['agent:create'], 'resources': ['*:*:*'], 'effect': 'allow'}, True),
    ({'actions': ['agent:read'], 'resources': ['agent:group:web&node:id:master'], 'effect': 'allow'}, True),
    # Effects the decorators do not evaluate as such
    ({'actions': ['agent:read'], 'resources': ['agent:id:*'], 'effect': 'maybe'}, False),
    ({'actions': ['agent:read'], 'resources': ['agent:id:*'], 'effect': ''}, False),
    # Actions and resource types missing from the catalog
    ({'actions': ['agent:bogus'], 'resources': ['agent:id:*'], 'effect': 'allow'}, False),
    ({'actions': ['agent:read'], 'resources': ['bogus:id:*'], 'effect': 'allow'}, False),
    ({'actions': ['agent:read'], 'resources': ['agent:bogusfield:*'], 'effect': 'allow'}, False),
    ({'actions': ['agent:read'], 'resources': ['agent:id:001&bogus:id:*'], 'effect': 'allow'}, False),
    ({'actions': ['agent:read'], 'resources': ['agent:id'], 'effect': 'allow'}, False),
    # Resources a token could not be built from (4500 for every holder of a linked role)
    ({'actions': ['agent:read'], 'resources': ['agent:group:web&node:id:master&agent:id:001'], 'effect': 'allow'},
     False),
    ({'actions': ['agent:read'], 'resources': ['agent:id:\u0660\u0660\u0661'], 'effect': 'allow'}, False),
    ({'actions': ['agent:read'], 'resources': ['agent:group:w\u00e9b'], 'effect': 'allow'}, False),
    # Empty lists grant or deny nothing
    ({'actions': [], 'resources': ['agent:id:*'], 'effect': 'allow'}, False),
    ({'actions': ['agent:read'], 'resources': [], 'effect': 'allow'}, False),
    ({'resources': ['agent:id:*'], 'effect': 'allow'}, False),
    (None, False),
])
def test_is_valid_rbac_policy(policy, expected):
    """Check that a policy is valid only with a known effect and catalog actions and resource types."""
    from wazuh.core.security import is_valid_rbac_policy

    assert is_valid_rbac_policy(policy) is expected


@pytest.mark.parametrize('policy', [
    {'actions': ['agent:read'], 'resources': ['agent:id:*'], 'effect': 'allow'},
    {'actions': ['agent:read', 'group:read'], 'resources': ['agent:id:001', 'group:id:default'], 'effect': 'deny'},
    {'actions': ['agent:create'], 'resources': ['*:*:*'], 'effect': 'allow'},
    {'actions': ['agent:read'], 'resources': ['agent:group:web&node:id:master'], 'effect': 'allow'},
    {'actions': ['agent:read'], 'resources': ['agent:group:web-1.a/b'], 'effect': 'allow'},
])
def test_a_stored_policy_builds_a_token(policy):
    """Whatever a policy write accepts, the token preprocessor accepts too.

    Otherwise a body stored through `PUT /security/policies` would make every holder of the linked roles
    fail authorization with 4500 on its next request.
    """
    from wazuh.core.security import is_valid_rbac_policy
    from wazuh.rbac.preprocessor import PreProcessor

    assert is_valid_rbac_policy(policy)
    PreProcessor().process_policy(policy)


def test_default_policies_are_valid():
    """The stricter write check still accepts every policy the installation seeds."""
    from wazuh.core.security import is_valid_rbac_policy

    with open(os.path.join(os.path.dirname(__file__), '..', '..', 'rbac', 'default', 'policies.yaml')) as f:
        defaults = yaml.safe_load(f)['default_policies']

    bodies = [body for group in defaults.values() for body in group['policies'].values()]
    assert bodies
    assert [body for body in bodies if not is_valid_rbac_policy(body)] == []


@pytest.mark.parametrize('rule, expected', [
    ({'FIND': {'user_name': 'admin'}}, True),
    ({'MATCH$': {'definition': 'normal_rule'}}, True),
    ({'OR': [{'MATCH': {'user': 'a'}}, {'FIND$': {'user': 'b'}}]}, True),
    ({'NOT': {'MATCH': {'user': 'a'}}}, True),
    ({'AND': [{'MATCH': {'user': 'a'}}, {'NOT': [{'FIND': {'group': 'b'}}]}]}, True),
    # Keys the authorization context never evaluates
    ({'bogus': 1}, False),
    ({'MATCH': {'user': 'a'}, 'bogus': 1}, False),
    ({'OR': [{'MATCH': {'user': 'a'}}, {'bogus': 1}]}, False),
    # Empty rules and operators never match; an empty function matches every context
    ({}, False),
    ({'OR': []}, False),
    ({'AND': {}}, False),
    ({'MATCH': {}}, False),
    ({'FIND': 'admin'}, False),
    ([{'MATCH': {'user': 'a'}}], False),
    (None, False),
])
def test_is_valid_security_rule(rule, expected):
    """Check that a security rule is valid only with the operators the authorization context evaluates."""
    from wazuh.core.security import is_valid_security_rule

    assert is_valid_security_rule(rule) is expected
