# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from unittest.mock import patch

import pytest
import yaml
from sqlalchemy import create_engine

from wazuh.rbac.tests.utils import init_db

test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data')


@pytest.fixture(scope='function')
def db_setup():
    with patch('wazuh.core.common.wazuh_uid'), patch('wazuh.core.common.wazuh_gid'):
        with patch('sqlalchemy.create_engine', return_value=create_engine("sqlite://")):
            with patch('shutil.chown'), patch('os.chmod'):
                with patch('wazuh.core.common.WAZUH_SERVER_YML', new=test_data_path):
                    import wazuh.rbac.orm as rbac
                    import wazuh.rbac.decorators
                    wazuh.rbac.decorators.rbac.set({'rbac_mode': 'white'})
    init_db('schema_security_test.sql', test_data_path)

    yield rbac


test_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))  # RBAC folder
default_configuration = os.path.join(test_path, 'default/')
with open(default_configuration + 'roles.yaml') as f:
    role_yaml = yaml.safe_load(f)
    roles = role_yaml[list(role_yaml.keys())[0]]
    roles_configuration = [(role_name, info['description']) for role_name, info in roles.items()]

with open(default_configuration + 'rules.yaml') as f:
    rule_yaml = yaml.safe_load(f)
    rules = rule_yaml[list(rule_yaml.keys())[0]]
    rules_configuration = [(rule_name, info['rule']) for rule_name, info in rules.items()]

with open(default_configuration + 'policies.yaml') as f:
    policy_yaml = yaml.safe_load(f)
    policies = policy_yaml[list(policy_yaml.keys())[0]]
    policies_configuration = list()
    for name, payload in policies.items():
        for sub_name, policy in payload['policies'].items():
            policies_configuration.append((f'{name}_{sub_name}', policy))

with open(default_configuration + 'users.yaml') as f:
    user_yaml = yaml.safe_load(f)
    users = user_yaml[list(user_yaml.keys())[0]]
    users_configuration = [(user, info['allow_run_as']) for user, info in users.items()]

with open(default_configuration + 'relationships.yaml') as f:
    file = yaml.safe_load(f)
    relationships = file[list(file.keys())[0]]
    user_roles = [(user, role_ids['role_ids']) for user, role_ids in relationships['users'].items()]
    role_policies = [(role, policy_ids['policy_ids']) for role, policy_ids in relationships['roles'].items()]


@pytest.mark.parametrize('role_name, role_description', roles_configuration)
def test_roles_default(db_setup, role_name, role_description):
    with db_setup.RolesManager() as rm:
        role = rm.get_role(name=role_name)
        assert role_name == role['name']


@pytest.mark.parametrize('rule_name, rule_info', rules_configuration)
def test_rules_default(db_setup, rule_name, rule_info):
    with db_setup.RulesManager() as rum:
        rule = rum.get_rule_by_name(rule_name=rule_name)
        assert rule_name == rule['name']
        assert rule_info == rule['rule']


@pytest.mark.parametrize('policy_name, policy_policy', policies_configuration)
def test_policies_default(db_setup, policy_name, policy_policy):
    with db_setup.PoliciesManager() as pm:
        current_policy = pm.get_policy(name=policy_name)
        assert policy_name == current_policy['name']
        assert policy_policy == current_policy['policy']


@pytest.mark.parametrize('user_name, auth_context', users_configuration)
def test_users_default(db_setup, user_name, auth_context):
    with db_setup.AuthenticationManager() as am:
        assert user_name == am.get_user(username=user_name)['username']
        assert auth_context == am.user_allow_run_as(username=user_name)


@pytest.mark.parametrize('user_name, role_ids', user_roles)
def test_user_roles_default(db_setup, user_name, role_ids):
    with db_setup.UserRolesManager() as urm:
        with db_setup.AuthenticationManager() as am:
            user_id = am.get_user(username=user_name)['id']
        db_roles = urm.get_all_roles_from_user(user_id=user_id)
        orm_role_names = [role.name for role in db_roles]
        assert set(role_ids) == set(orm_role_names)


@pytest.mark.parametrize('role_name, policy_names', role_policies)
def test_role_policies_default(db_setup, role_name, policy_names):
    with db_setup.RolesPoliciesManager() as rpm:
        with db_setup.RolesManager() as rm:
            db_policies = rpm.get_all_policies_from_role(role_id=rm.get_role(name=role_name)['id'])
            orm_policy_names = [policy.name for policy in db_policies]
            for current_policy in orm_policy_names:
                current_policy = '_'.join(current_policy.split('_')[:2])
                assert current_policy in policy_names
