# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from unittest.mock import patch

import pytest
import yaml
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

import wazuh.rbac.decorators
import wazuh.rbac.orm as orm
from wazuh import security

test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data')


def create_memory_db(sql_file, session):
    with open(os.path.join(test_data_path, sql_file)) as f:
        for line in f.readlines():
            line = line.strip()
            if '* ' not in line and '/*' not in line and '*/' not in line and line != '':
                session.execute(line)
                session.commit()


@pytest.fixture(scope='module')
def db_setup():
    def _method(session):
        try:
            create_memory_db('schema_initial_security_test.sql', session)
        except OperationalError:
            pass

    return _method


@pytest.fixture(scope='module')
def import_RBAC(db_setup):
    with patch('api.constants.SECURITY_PATH', new=test_data_path):
        import wazuh.rbac.orm as rbac
        with patch('wazuh.security.orm._engine', create_engine(f'sqlite://')):
            with patch('wazuh.security.orm._Session', sessionmaker(bind=create_engine(f'sqlite://'))):
                db_setup(security.orm._Session())
                yield rbac


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
def test_roles_default(import_RBAC, role_name, role_rule):
    with import_RBAC.RolesManager() as rm:
        role = rm.get_role(name=role_name)
        assert role_name == role['name']
        assert role_rule == role['rule']


@pytest.mark.parametrize('policy_name, policy_policy', policies_configuration)
def test_policies_default(import_RBAC, policy_name, policy_policy):
    with import_RBAC.PoliciesManager() as pm:
        policy = pm.get_policy(name=policy_name)
        assert policy_name == policy['name']
        assert policy_policy == policy['policy']


@pytest.mark.parametrize('user_name, auth_context', users_configuration)
def test_users_default(import_RBAC, user_name, auth_context):
    with import_RBAC.AuthenticationManager() as am:
        assert user_name == am.get_user(username=user_name)['username']
        assert auth_context == am.user_auth_context(username=user_name)


@pytest.mark.parametrize('user_name, role_ids', user_roles)
def test_user_roles_default(import_RBAC, user_name, role_ids):
    with import_RBAC.UserRolesManager() as urm:
        db_roles = urm.get_all_roles_from_user(username=user_name)
        orm_role_names = [role.name for role in db_roles]
        assert set(role_ids) == set(orm_role_names)


@pytest.mark.parametrize('role_name, policy_names', role_policies)
def test_role_policies_default(import_RBAC, role_name, policy_names):
    with import_RBAC.RolesPoliciesManager() as rpm:
        with import_RBAC.RolesManager() as rm:
            db_policies = rpm.get_all_policies_from_role(role_id=rm.get_role(name=role_name)['id'])
            orm_policy_names = [policy.name for policy in db_policies]
            assert set(orm_policy_names) == set(policy_names)
