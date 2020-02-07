# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import yaml
import os

import pytest

import wazuh.rbac.decorators
import wazuh.rbac.orm as orm

wazuh.rbac.decorators.switch_mode('black')
test_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))  # RBAC folder
default_configuration = os.path.join(test_path, 'default/')
with open(default_configuration + 'roles.yaml') as f:
    role_yaml = yaml.safe_load(f)
    roles = role_yaml[list(role_yaml.keys())[0]]
    roles_configuration = [(role_name, info['rule']) for role_name, info in roles.items()]

with open(default_configuration + 'policies.yaml') as f:
    policy_yaml = yaml.safe_load(f)
    policies = policy_yaml[list(policy_yaml.keys())[0]]
    policies_configuration = [(policy_name, info['policy']) for policy_name, info in policies.items()]

with open(default_configuration + 'users.yaml') as f:
    user_yaml = yaml.safe_load(f)
    users = user_yaml[list(user_yaml.keys())[0]]
    users_configuration = [(user, info['auth_context']) for user, info in users.items()]

with open(default_configuration + 'relationships.yaml') as f:
    file = yaml.safe_load(f)
    relationships = file[list(file.keys())[0]]
    user_roles = [(user, role_ids['role_ids']) for user, role_ids in relationships['users'].items()]
    role_policies = [(role, policy_ids['policy_ids']) for role, policy_ids in relationships['roles'].items()]


@pytest.mark.parametrize('role_name, role_rule', roles_configuration)
def test_roles_default(role_name, role_rule):
    with orm.RolesManager() as rm:
        role = rm.get_role(name=role_name)
        assert role_name == role['name']
        assert role_rule == role['rule']


@pytest.mark.parametrize('policy_name, policy_policy', policies_configuration)
def test_policies_default(policy_name, policy_policy):
    with orm.PoliciesManager() as pm:
        policy = pm.get_policy(name=policy_name)
        assert policy_name == policy['name']
        assert policy_policy == policy['policy']


@pytest.mark.parametrize('user_name, auth_context', users_configuration)
def test_users_default(user_name, auth_context):
    with orm.AuthenticationManager() as am:
        assert user_name == am.get_user(username=user_name)['username']
        assert auth_context == am.user_auth_context(username=user_name)


@pytest.mark.parametrize('user_name, role_ids', user_roles)
def test_user_roles_default(user_name, role_ids):
    with orm.UserRolesManager() as urm:
        assert role_ids == urm.get_all_roles_from_user(username=user_name)


@pytest.mark.parametrize('role_name, policy_names', role_policies)
def test_role_policies_default(role_name, policy_names):
    with orm.RolesPoliciesManager() as rpm:
        with orm.RolesManager() as rm, orm.PoliciesManager() as pm:
            role_id = rm.get_role(name=role_name)['id']
            policy_ids = rpm.get_all_policies_from_role(role_id=role_id)
            orm_policy_names = [pm.get_policy_id(policy_id)['name'] for policy_id in policy_ids]
            assert set(orm_policy_names) == set(policy_names)
