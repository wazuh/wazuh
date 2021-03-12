#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2


import glob
import os
from contextvars import ContextVar
from importlib import reload
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from yaml import safe_load

from wazuh.core.exception import WazuhError

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data', 'security/')

# Params

security_cases = list()
rbac_cases = list()
default_orm_engine = create_engine("sqlite:///:memory:")
os.chdir(test_data_path)

for file in glob.glob('*.yml'):
    with open(os.path.join(test_data_path + file)) as f:
        tests_cases = safe_load(f)

    for function_, test_cases in tests_cases.items():
        for test_case in test_cases:
            if file != 'rbac_catalog.yml':
                security_cases.append((function_, test_case['params'], test_case['result']))
            else:
                rbac_cases.append((function_, test_case['params'], test_case['result']))


def create_memory_db(sql_file, session):
    with open(os.path.join(test_data_path, sql_file)) as f:
        for line in f.readlines():
            line = line.strip()
            if '* ' not in line and '/*' not in line and '*/' not in line and line != '':
                session.execute(line)
                session.commit()


def reload_default_rbac_resources():
    with patch('wazuh.core.common.ossec_uid'), patch('wazuh.core.common.ossec_gid'):
        with patch('sqlalchemy.create_engine', return_value=default_orm_engine):
            with patch('shutil.chown'), patch('os.chmod'):
                import wazuh.rbac.orm as orm
                reload(orm)
                import wazuh.rbac.decorators as decorators
                from wazuh.tests.util import RBAC_bypasser

                decorators.expose_resources = RBAC_bypasser
                from wazuh import security
    return security, orm


@pytest.fixture(scope='function')
def db_setup():
    with patch('wazuh.core.common.ossec_uid'), patch('wazuh.core.common.ossec_gid'):
        with patch('sqlalchemy.create_engine', return_value=create_engine("sqlite://")):
            with patch('shutil.chown'), patch('os.chmod'):
                with patch('api.constants.SECURITY_PATH', new=test_data_path):
                    import wazuh.rbac.orm as orm
                    reload(orm)
                    import wazuh.rbac.decorators as decorators
                    from wazuh.tests.util import RBAC_bypasser

                    decorators.expose_resources = RBAC_bypasser
                    from wazuh import security
                    from wazuh.core.results import WazuhResult
                    from wazuh.core import security as core_security
    try:
        create_memory_db('schema_security_test.sql', orm._Session())
    except OperationalError:
        pass

    yield security, WazuhResult, core_security


@pytest.fixture(scope='function')
def new_default_resources():
    global default_orm_engine
    default_orm_engine = create_engine("sqlite:///:memory:")

    security, orm = reload_default_rbac_resources()

    with open(os.path.join(test_data_path, 'default', 'default_cases.yml')) as f:
        new_resources = safe_load(f)

    for function_, cases in new_resources.items():
        for case in cases:
            getattr(security, function_)(**case['params']).to_dict()

    return security, orm


def affected_are_equal(target_dict, expected_dict):
    return target_dict['affected_items'] == expected_dict['affected_items']


def failed_are_equal(target_dict, expected_dict):
    if len(target_dict['failed_items'].keys()) == 0 and len(expected_dict['failed_items'].keys()) == 0:
        return True
    result = False
    for target_key, target_value in target_dict['failed_items'].items():
        for expected_key, expected_value in expected_dict['failed_items'].items():
            result = expected_key in str(target_key) and set(target_value) == set(expected_value)
            if result:
                break

    return result


@pytest.mark.parametrize('security_function, params, expected_result', security_cases)
def test_security(db_setup, security_function, params, expected_result):
    """Verify the entire security module.

    Parameters
    ----------
    db_setup : callable
        This function creates the rbac.db file.
    security_function : list of str
        This is the name of the tested function.
    params : list of str
        Arguments for the tested function.
    expected_result : list of dict
        This is a list that contains the expected results .
    """
    try:
        security, _, _ = db_setup
        result = getattr(security, security_function)(**params).to_dict()
        assert affected_are_equal(result, expected_result)
        assert failed_are_equal(result, expected_result)
    except WazuhError as e:
        assert str(e.code) == list(expected_result['failed_items'].keys())[0]


@pytest.mark.parametrize('security_function, params, expected_result', rbac_cases)
def test_rbac_catalog(db_setup, security_function, params, expected_result):
    """Verify RBAC catalog functions.

    Parameters
    ----------
    db_setup : callable
        This function creates the rbac.db file.
    security_function : list of str
        This is the name of the tested function.
    params : list of str
        Arguments for the tested function.
    expected_result : list of dict
        This is a list that contains the expected results .
    """
    security, _, _ = db_setup
    final_params = dict()
    for param, value in params.items():
        if value.lower() != 'none':
            final_params[param] = value
    result = getattr(security, security_function)(**final_params).to_dict()
    assert result['result']['data'] == expected_result


def test_revoke_tokens(db_setup):
    """Checks that the return value of revoke_tokens is a WazuhResult."""
    with patch('wazuh.core.security.change_secret', side_effect=None):
        security, WazuhResult, _ = db_setup
        mock_current_user = ContextVar('current_user', default='wazuh')
        with patch("wazuh.sca.common.current_user", new=mock_current_user):
            result = security.revoke_current_user_tokens()
            assert isinstance(result, WazuhResult)


@pytest.mark.parametrize('role_list, expected_users', [
    ([100, 101], {100, 103, 102}),
    ([102], {104}),
    ([102, 103, 104], {101, 104, 102})
])
def test_check_relationships(db_setup, role_list, expected_users):
    """Check that the relationship between role and user is correct according to
    `schema_security_test.sql`.

    Parameters
    ----------
    role_list : list
        List of role IDs.
    expected_users : set
        Expected users.
    """
    _, _, core_security = db_setup
    assert core_security.check_relationships(roles=[role_id for role_id in role_list]) == expected_users


@pytest.mark.parametrize('user_list, expected_users', [
    ([104], {104}),
    ([102, 103], {102, 103}),
    ([], set())
])
def test_invalid_users_tokens(db_setup, user_list, expected_users):
    """Check that the argument passed to `TokenManager.add_user_roles_rules` formed by `users` is correct.

    Parameters
    ----------
    user_list : list
        List of users.
    expected_users : set
        Expected users.
    """
    with patch('wazuh.security.TokenManager.add_user_roles_rules') as TM_mock:
        _, _, core_security = db_setup
        core_security.invalid_users_tokens(users=[user_id for user_id in user_list])
        related_users = TM_mock.call_args.kwargs['users']
        assert set(related_users) == expected_users


@pytest.mark.parametrize('role_list, expected_roles', [
    ([104], {104}),
    ([102, 103], {102, 103}),
    ([], set())
])
def test_invalid_roles_tokens(db_setup, role_list, expected_roles):
    """Check that the argument passed to `TokenManager.add_user_roles_rules` formed by `roles` is correct.

    Parameters
    ----------
    role_list : list
        List of roles.
    expected_roles : set
        Expected roles.
    """
    with patch('wazuh.security.TokenManager.add_user_roles_rules') as TM_mock:
        _, _, core_security = db_setup
        core_security.invalid_roles_tokens(roles=[role_id for role_id in role_list])
        assert set(TM_mock.call_args.kwargs['roles']) == expected_roles


def test_add_new_default_policies(new_default_resources):
    """Check that new default policies are set in the correct range and that the migration proccess moves any possible
    default policy in the user range to the default range."""

    def mock_open_default_resources(*args, **kwargs):
        args = list(args)
        file_path = args[0]

        if file_path.endswith('policies.yaml'):
            new_args = [os.path.join(test_data_path, 'default', 'new_default_policies.yml')]
        elif file_path.endswith('relationships.yaml'):
            new_args = [os.path.join(test_data_path, 'default', 'mock_relationships.yml')]
        else:
            new_args = [file_path]

        new_args += args[1:]

        return open(*new_args, **kwargs)

    security, orm = new_default_resources
    with orm.PoliciesManager() as pm:
        policies = sorted([p.id for p in pm.get_policies()]) or [1]
        max_default_policy_id = max(filter(lambda x: not (x > orm.cloud_reserved_range), policies))

    with patch('wazuh.rbac.orm.open', side_effect=mock_open_default_resources):
        security, orm = reload_default_rbac_resources()

    with orm.PoliciesManager() as pm:
        new_policies = sorted([p.id for p in pm.get_policies()]) or [1]
        new_max_default_policy_id = max(filter(lambda x: not (x > orm.cloud_reserved_range), new_policies))

    assert len(policies) + 1 == len(new_policies)
    assert max(policies) == max(new_policies)
    assert max_default_policy_id + 2 == new_max_default_policy_id


def test_migrate_default_policies(new_default_resources):
    """Check that the migration process overwrites default policies in the user range including their relationships
    and positions."""
    def mock_open_default_resources(*args, **kwargs):
        args = list(args)
        file_path = args[0]

        if file_path.endswith('policies.yaml'):
            new_args = [os.path.join(test_data_path, 'default', 'migration_policies.yml')]
        elif file_path.endswith('relationships.yaml'):
            new_args = [os.path.join(test_data_path, 'default', 'mock_relationships.yml')]
        else:
            new_args = [file_path]

        new_args += args[1:]

        return open(*new_args, **kwargs)

    security, orm = new_default_resources
    with orm.RolesManager() as rm:
        role1, role2 = rm.get_role('new_role1')['id'], rm.get_role('new_role2')['id']
    policy1, policy2 = 'new_policy1', 'new_policy2'
    user_policy = 'user_policy'
    with orm.PoliciesManager() as pm:
        policies = sorted([p.id for p in pm.get_policies()]) or [1]
        max_default_policy_id = max(filter(lambda x: not (x > orm.cloud_reserved_range), policies))

    with orm.RolesPoliciesManager() as rpm:
        role1_policies = [p.id for p in rpm.get_all_policies_from_role(role_id=role1)]
        role2_policies = [p.id for p in rpm.get_all_policies_from_role(role_id=role2)]

    # Assert these new policies are in the user range
    with orm.PoliciesManager() as pm:
        policy1_id = pm.get_policy(policy1)['id']
        policy2_id = pm.get_policy(policy2)['id']
        user_policy_id = pm.get_policy(user_policy)['id']
        assert policy1_id > orm.max_id_reserved
        assert policy2_id > orm.max_id_reserved
        assert user_policy_id > orm.max_id_reserved
        assert {policy1_id, policy2_id, user_policy_id} == set(role1_policies)
        assert {policy1_id, policy2_id, user_policy_id} == set(role2_policies)

    with patch('wazuh.rbac.orm.open', side_effect=mock_open_default_resources):
        security, orm = reload_default_rbac_resources()

    with orm.RolesPoliciesManager() as rpm:
        new_role1_policies = [p.id for p in rpm.get_all_policies_from_role(role_id=role1)]
        new_role2_policies = [p.id for p in rpm.get_all_policies_from_role(role_id=role2)]

    new_policy1_id, new_policy2_id = max_default_policy_id + 1, max_default_policy_id + 2
    with orm.PoliciesManager() as pm:
        assert new_policy1_id == pm.get_policy(policy1)['id']
        assert new_policy2_id == pm.get_policy(policy2)['id']

    assert role1_policies.index(policy1_id) == new_role1_policies.index(new_policy1_id)
    assert role1_policies.index(policy2_id) == new_role1_policies.index(new_policy2_id)

    assert role2_policies.index(policy1_id) == new_role2_policies.index(new_policy1_id)
    assert role2_policies.index(policy2_id) == new_role2_policies.index(new_policy2_id)

    assert role1_policies.index(user_policy_id) == new_role1_policies.index(user_policy_id)
    assert role2_policies.index(user_policy_id) == new_role2_policies.index(user_policy_id)
