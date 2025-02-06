# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
import re
from importlib import reload
from unittest.mock import MagicMock, call, patch

import pytest
import yaml
from sqlalchemy import Column, String, create_engine
from sqlalchemy import orm as sqlalchemy_orm
from sqlalchemy.exc import OperationalError
from sqlalchemy.sql import text
from wazuh.core.utils import get_utc_now
from wazuh.rbac.orm import (
    MAX_ID_RESERVED,
    WAZUH_USER_ID,
    WAZUH_WUI_USER_ID,
    Policies,
    Roles,
    RolesPolicies,
    RolesRules,
    Rules,
    SecurityError,
    User,
    UserRoles,
)
from wazuh.rbac.tests.utils import MockedUserRole, MockRolePolicy, MockRoleRules, init_db

test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data')
in_memory_db_path = ":memory:"


@pytest.fixture(scope='function')
def db_setup():
    with patch('wazuh.core.common.wazuh_uid'), patch('wazuh.core.common.wazuh_gid'):
        with patch('sqlalchemy.create_engine', return_value=create_engine("sqlite://")):
            with patch('shutil.chown'), patch('os.chmod'):
                import wazuh.rbac.orm as rbac
                # Clear mappers
                sqlalchemy_orm.clear_mappers()

    init_db('schema_security_test.sql', test_data_path)

    yield rbac


@pytest.fixture(scope="function")
def fresh_in_memory_db():
    # Clear mappers
    sqlalchemy_orm.clear_mappers()

    # Create fresh in-memory db
    with patch('wazuh.core.common.wazuh_uid'), patch('wazuh.core.common.wazuh_gid'):
        import wazuh.rbac.orm as orm
        reload(orm)

        orm.db_manager.close_sessions()
        orm.db_manager.connect(in_memory_db_path)
        orm.db_manager.create_database(in_memory_db_path)

    yield orm

    orm.db_manager.close_sessions()


def test_database_init(db_setup):
    """Check users db is properly initialized"""
    with db_setup.RolesManager() as rm:
        assert rm.get_role('wazuh') != db_setup.SecurityError.ROLE_NOT_EXIST

def add_token(db_setup):
    """Store a new token rule in the database"""
    with db_setup.TokenManager() as tm:
        users = {'newUser', 'newUser1'}
        roles = {'test', 'test1', 'test2'}
        with db_setup.AuthenticationManager() as am:
            for user in users:
                am.add_user(username=user, password='testingA1!')
        with db_setup.RolesManager() as rm:
            for role in roles:
                rm.add_role(name=role)
        with db_setup.AuthenticationManager() as am:
            user_ids = [am.get_user(user)['id'] for user in users]
        with db_setup.RolesManager() as rm:
            role_ids = [rm.get_role(role)['id'] for role in roles]

        # New token rule
        assert tm.add_user_roles_rules(users=user_ids) != db_setup.SecurityError.ALREADY_EXIST
        assert tm.add_user_roles_rules(roles=role_ids) != db_setup.SecurityError.ALREADY_EXIST

    return user_ids, role_ids


def test_get_all_token_rules(db_setup):
    """Check that rules are correctly created"""
    users, roles = add_token(db_setup)
    with db_setup.TokenManager() as tm:
        user_rules, role_rules, run_as_rules = tm.get_all_rules()
        for user in user_rules.keys():
            assert user in users
        for role in role_rules.keys():
            assert role in roles
        assert isinstance(run_as_rules, dict)


def test_nbf_invalid(db_setup):
    """Check if a user's token is valid by comparing the values with those stored in the database"""
    current_timestamp = int(get_utc_now().timestamp())
    users, roles = add_token(db_setup)
    with db_setup.TokenManager() as tm:
        for user in users:
            assert not tm.is_token_valid(user_id=user, token_nbf_time=current_timestamp)
        for role in roles:
            assert not tm.is_token_valid(role_id=role, token_nbf_time=current_timestamp)


def test_delete_all_rules(db_setup):
    """Check that rules are correctly deleted"""
    add_token(db_setup)
    with db_setup.TokenManager() as tm:
        assert tm.delete_all_rules()


def test_delete_all_expired_rules(db_setup):
    """Check that rules are correctly deleted"""
    with patch('wazuh.rbac.orm.time', return_value=0):
        add_token(db_setup)
    with db_setup.TokenManager() as tm:
        assert tm.delete_all_expired_rules()


def test_add_user(db_setup):
    """Check user is added to database"""
    with db_setup.AuthenticationManager() as am:
        # New user
        am.add_user(username='newUser', password='testingA1!')
        assert am.get_user(username='newUser')
        # New user
        am.add_user(username='newUser1', password='testingA2!')
        assert am.get_user(username='newUser1')

        assert not am.add_user(username='newUser1', password='testingA2!')

        # Obtain not existent user
        assert not am.get_user('noexist')


def test_add_role(db_setup):
    """Check role is added to database"""
    with db_setup.RolesManager() as rm:
        # New role
        rm.add_role('newRole')
        assert rm.get_role('newRole')
        # New role
        rm.add_role('newRole1')
        assert rm.get_role('newRole1')

        # Obtain not existent role
        assert rm.get_role('noexist') == db_setup.SecurityError.ROLE_NOT_EXIST


def test_add_policy(db_setup):
    """Check policy is added to database"""
    with db_setup.PoliciesManager() as pm:
        # New policy
        policy = {
            'actions': ['agents:update'],
            'resources': [
                'agent:id:001', 'agent:id:002', 'agent:id:003'
            ],
            'effect': 'allow'
        }
        pm.add_policy(name='newPolicy', policy=policy)
        assert pm.get_policy('newPolicy')
        # New policy
        policy['actions'] = ['agents:delete']
        pm.add_policy(name='newPolicy1', policy=policy)
        assert pm.get_policy('newPolicy1')

        # Obtain not existent policy
        assert pm.get_policy('noexist') == db_setup.SecurityError.POLICY_NOT_EXIST


def test_add_rule(db_setup):
    """Check rules in the database"""
    with db_setup.RulesManager() as rum:
        # New rule
        rum.add_rule(name='test_rule', rule={'MATCH': {'admin': ['admin_role']}})

        assert rum.get_rule_by_name(rule_name='test_rule')

        # Obtain not existent role
        assert rum.get_rule(999) == db_setup.SecurityError.RULE_NOT_EXIST
        assert rum.get_rule_by_name('not_exists') == db_setup.SecurityError.RULE_NOT_EXIST


def test_get_user(db_setup):
    """Check users in the database"""
    with db_setup.AuthenticationManager() as am:
        users = am.get_users()
        assert users
        for user in users:
            assert isinstance(user['user_id'], int)

        assert users[0]['user_id'] == 1


def test_get_roles(db_setup):
    """Check roles in the database"""
    with db_setup.RolesManager() as rm:
        roles = rm.get_roles()
        assert roles
        for rol in roles:
            assert isinstance(rol.name, str)

        assert roles[0].name == 'administrator'


def test_get_policies(db_setup):
    """Check policies in the database"""
    with db_setup.PoliciesManager() as pm:
        policies = pm.get_policies()
        assert policies
        for policy in policies:
            assert isinstance(policy.name, str)
            assert isinstance(json.loads(policy.policy), dict)

        assert policies[1].name == 'agents_all_agents'


def test_get_rules(db_setup):
    """Check rules in the database"""
    with db_setup.RulesManager() as rum:
        rules = rum.get_rules()
        assert rules
        for rule in rules:
            assert isinstance(rule.name, str)
            assert isinstance(json.loads(rule.rule), dict)

        # Last rule in the database
        assert rules[-1].name == 'rule6'


def test_delete_users(db_setup):
    """Check delete users in the database"""
    with db_setup.AuthenticationManager() as am:
        am.add_user(username='toDelete', password='testingA3!')
        len_users = len(am.get_users())
        am.delete_user(user_id=106)
        assert len_users == len(am.get_users()) + 1


def test_delete_roles(db_setup):
    """Check delete roles in the database"""
    with db_setup.RolesManager() as rm:
        rm.add_role(name='toDelete')
        len_roles = len(rm.get_roles())
        assert rm.delete_role_by_name(role_name='toDelete')
        assert len_roles == len(rm.get_roles()) + 1


def test_delete_all_roles(db_setup):
    """Check delete roles in the database"""
    with db_setup.RolesManager() as rm:
        assert rm.delete_all_roles()
        rm.add_role(name='toDelete')
        rm.add_role(name='toDelete1')
        len_roles = len(rm.get_roles())
        assert rm.delete_all_roles()
        assert len_roles == len(rm.get_roles()) + 2


def test_delete_rules(db_setup):
    """Check delete rules in the database"""
    with db_setup.RulesManager() as rum:
        rum.add_rule(name='toDelete', rule={'Unittest': 'Rule'})
        rum.add_rule(name='toDelete2', rule={'Unittest': 'Rule2'})
        len_rules = len(rum.get_rules())
        assert rum.delete_rule_by_name(rule_name='toDelete')
        assert len_rules == len(rum.get_rules()) + 1

        for rule in rum.get_rules():
            # Admin rules
            if rule.id < db_setup.MAX_ID_RESERVED:
                assert rum.delete_rule(rule.id) == db_setup.SecurityError.ADMIN_RESOURCES
            # Other rules
            else:
                assert rum.delete_rule(rule.id)


def test_delete_all_security_rules(db_setup):
    """Check delete all rules in the database"""
    with db_setup.RulesManager() as rum:
        assert rum.delete_all_rules()
        # Only admin rules are left
        assert all(rule.id < db_setup.MAX_ID_RESERVED for rule in rum.get_rules())
        rum.add_rule(name='toDelete', rule={'Unittest': 'Rule'})
        rum.add_rule(name='toDelete1', rule={'Unittest1': 'Rule'})
        len_rules = len(rum.get_rules())
        assert rum.delete_all_rules()
        assert len_rules == len(rum.get_rules()) + 2


def test_delete_policies(db_setup):
    """Check delete policies in the database"""
    with db_setup.PoliciesManager() as pm:
        policy = {
            'actions': ['agents:update'],
            'resources': [
                'agent:id:001', 'agent:id:003'
            ],
            'effect': 'allow'
        }
        assert pm.add_policy(name='toDelete', policy=policy) is True
        len_policies = len(pm.get_policies())
        assert pm.delete_policy_by_name(policy_name='toDelete')
        assert len_policies == len(pm.get_policies()) + 1


def test_delete_all_policies(db_setup):
    """Check delete policies in the database"""
    with db_setup.PoliciesManager() as pm:
        assert pm.delete_all_policies()
        policy = {
            'actions': ['agents:update'],
            'resources': [
                'agent:id:001', 'agent:id:003'
            ],
            'effect': 'allow'
        }
        pm.add_policy(name='toDelete', policy=policy)
        policy['actions'] = ['agents:delete']
        pm.add_policy(name='toDelete1', policy=policy)
        len_policies = len(pm.get_policies())
        pm.delete_all_policies()
        assert len_policies == len(pm.get_policies()) + 2


def test_edit_run_as(db_setup):
    """Check update a user's allow_run_as flag in the database"""
    with db_setup.AuthenticationManager() as am:
        am.add_user(username='runas', password='testingA6!')
        assert am.edit_run_as(user_id='106', allow_run_as=True)
        assert am.edit_run_as(user_id='106', allow_run_as="INVALID") == db_setup.SecurityError.INVALID
        assert not am.edit_run_as(user_id='999', allow_run_as=False)


def test_update_user(db_setup):
    """Check update a user in the database"""
    with db_setup.AuthenticationManager() as am:
        am.add_user(username='toUpdate', password='testingA6!')
        assert am.update_user(user_id='106', password='testingA0!')
        assert not am.update_user(user_id='999', password='testingA0!')


def test_update_role(db_setup):
    """Check update a role in the database"""
    with db_setup.RolesManager() as rm:
        rm.add_role(name='toUpdate')
        tid = rm.get_role_id(role_id=106)['id']
        tname = rm.get_role(name='toUpdate')['name']
        rm.update_role(role_id=tid, name='updatedName')
        assert tid == rm.get_role(name='updatedName')['id']
        assert tname == 'toUpdate'
        assert rm.get_role(name='updatedName')['name'] == 'updatedName'


def test_update_rule(db_setup):
    """Check update a rule in the database"""
    with db_setup.RulesManager() as rum:
        tname = 'toUpdate'
        rum.add_rule(name=tname, rule={'Unittest': 'Rule'})
        tid = rum.get_rule_by_name(rule_name=tname)['id']
        rum.update_rule(rule_id=tid, name='updatedName', rule={'Unittest1': 'Rule'})
        assert rum.get_rule_by_name(rule_name=tname) == db_setup.SecurityError.RULE_NOT_EXIST
        assert tid == rum.get_rule_by_name(rule_name='updatedName')['id']
        assert rum.get_rule(rule_id=tid)['name'] == 'updatedName'


def test_update_policy(db_setup):
    """Check update a policy in the database"""
    with db_setup.PoliciesManager() as pm:
        policy = {
            'actions': ['agents:update'],
            'resources': [
                'agent:id:004', 'agent:id:003'
            ],
            'effect': 'allow'
        }
        pm.add_policy(name='toUpdate', policy=policy)
        tid = pm.get_policy_id(policy_id=110)['id']
        tname = pm.get_policy(name='toUpdate')['name']
        policy['effect'] = 'deny'
        pm.update_policy(policy_id=tid, name='updatedName', policy=policy)
        assert tid == pm.get_policy(name='updatedName')['id']
        assert tname == 'toUpdate'
        assert pm.get_policy(name='updatedName')['name'] == 'updatedName'


def add_policy_role(db_setup):
    """Check role-policy relation is added to database"""
    with db_setup.RolesPoliciesManager() as rpm:
        with db_setup.PoliciesManager() as pm:
            assert pm.delete_all_policies()
        with db_setup.RolesManager() as rm:
            assert rm.delete_all_roles()

        policies_ids = list()
        roles_ids = list()

        with db_setup.RolesManager() as rm:
            rm.add_role(name='normal')
            roles_ids.append(rm.get_role('normal')['id'])
            rm.add_role(name='advanced')
            roles_ids.append(rm.get_role('advanced')['id'])

        with db_setup.PoliciesManager() as pm:
            policy = {
                'actions': ['agents:update'],
                'resources': [
                    'agent:id:002', 'agent:id:003'
                ],
                'effect': 'allow'
            }
            pm.add_policy('normalPolicy', policy)
            policies_ids.append(pm.get_policy('normalPolicy')['id'])
            policy['effect'] = 'deny'
            pm.add_policy('advancedPolicy', policy)
            policies_ids.append(pm.get_policy('advancedPolicy')['id'])

        # New role-policy
        for policy in policies_ids:
            for role in roles_ids:
                rpm.add_policy_to_role(role_id=role, policy_id=policy)

        rpm.get_all_policies_from_role(role_id=roles_ids[0])
        for policy in policies_ids:
            for role in roles_ids:
                assert rpm.exist_policy_role(role_id=role, policy_id=policy)


def add_user_roles(db_setup):
    """Store a new user-roles relation in the database"""
    with db_setup.RolesManager() as rm:
        pass
    with db_setup.UserRolesManager() as urm:
        with db_setup.AuthenticationManager() as am:
            for user in am.get_users():
                result = am.delete_user(user_id=user['user_id'])
                if result is True:
                    assert not am.get_user_id(user_id=user['user_id'])
                    assert len(urm.get_all_roles_from_user(user_id=user['user_id'])) == 0
                else:
                    assert am.get_user_id(user_id=user['user_id'])
                    assert len(urm.get_all_roles_from_user(user_id=user['user_id'])) > 0
        with db_setup.RolesManager() as rm:
            assert rm.delete_all_roles()

        user_list = list()
        roles_ids = list()

        with db_setup.AuthenticationManager() as am:
            assert am.add_user(username='normalUser', password='testingA1!')
            user_list.append(am.get_user('normalUser')['id'])
            assert am.add_user(username='normalUser1', password='testingA1!')
            user_list.append(am.get_user('normalUser1')['id'])

        with db_setup.RolesManager() as rm:
            assert rm.add_role('normal')
            roles_ids.append(rm.get_role('normal')['id'])
            assert rm.add_role('advanced')
            roles_ids.append(rm.get_role('advanced')['id'])

        # New user-role
        for user in user_list:
            for role in roles_ids:
                assert urm.add_role_to_user(user_id=user, role_id=role)

        return user_list, roles_ids


def add_role_rule(db_setup):
    """Store a new roles-rules relation in the database"""
    with db_setup.RolesRulesManager() as rrum:
        with db_setup.RulesManager() as rum:
            rum.delete_all_rules()
        with db_setup.RolesManager() as rm:
            assert rm.delete_all_roles()

        rule_ids = list()
        role_ids = list()

        with db_setup.RulesManager() as rum:
            assert rum.add_rule(name='normalRule', rule={'rule': ['testing']})
            rule_ids.append(rum.get_rule_by_name('normalRule')['id'])
            assert rum.add_rule(name='normalRule1', rule={'rule1': ['testing1']})
            rule_ids.append(rum.get_rule_by_name('normalRule1')['id'])

        with db_setup.RolesManager() as rm:
            assert rm.add_role('normal')
            role_ids.append(rm.get_role('normal')['id'])
            assert rm.add_role('advanced')
            role_ids.append(rm.get_role('advanced')['id'])

        # New role-rule
        for role in role_ids:
            for rule in rule_ids:
                assert rrum.add_rule_to_role(rule_id=rule, role_id=role)
                assert rrum.exist_role_rule(rule_id=rule, role_id=role)

        return role_ids, rule_ids

def add_role_policy(db_setup):
    """Store a new role-policy relation in the database"""
    with db_setup.RolesPoliciesManager() as rpm:
        with db_setup.PoliciesManager() as pm:
            assert pm.delete_all_policies()
        with db_setup.RolesManager() as rm:
            assert rm.delete_all_roles()

        policies_ids = list()
        roles_ids = list()

        with db_setup.RolesManager() as rm:
            rm.add_role('normalUnit')
            roles_ids.append(rm.get_role('normalUnit')['id'])
            rm.add_role('advancedUnit')
            roles_ids.append(rm.get_role('advancedUnit')['id'])

        with db_setup.PoliciesManager() as pm:
            policy = {
                'actions': ['agents:update'],
                'resources': [
                    'agent:id:005', 'agent:id:003'
                ],
                'effect': 'allow'
            }
            pm.add_policy('normalPolicyUnit', policy)
            policies_ids.append(pm.get_policy('normalPolicyUnit')['id'])
            policy['actions'] = ['agents:create']
            pm.add_policy('advancedPolicyUnit', policy)
            policies_ids.append(pm.get_policy('advancedPolicyUnit')['id'])
        # New role-policy
        for policy in policies_ids:
            for role in roles_ids:
                rpm.add_role_to_policy(policy_id=policy, role_id=role)
        for policy in policies_ids:
            for role in roles_ids:
                assert rpm.exist_role_policy(policy_id=policy, role_id=role)

        return policies_ids, roles_ids


def test_add_user_role_level(db_setup):
    """Check user-role relation is added with level to database"""
    with db_setup.UserRolesManager() as urm:
        with db_setup.AuthenticationManager() as am:
            for user in am.get_users():
                assert am.delete_user(user_id=user['user_id'])
        with db_setup.RolesManager() as rm:
            assert rm.delete_all_roles()

        roles_ids = list()

        with db_setup.AuthenticationManager() as am:
            assert am.add_user(username='normal_level', password='testingA1!')
            user_id = am.get_user(username='normal_level')['id']

        with db_setup.RolesManager() as rm:
            assert rm.add_role('normal')
            roles_ids.append(rm.get_role('normal')['id'])
            assert rm.add_role('advanced')
            roles_ids.append(rm.get_role('advanced')['id'])

        # New role-policy
        for role in roles_ids:
            urm.add_role_to_user(user_id=user_id, role_id=role)
        for role in roles_ids:
            assert urm.exist_user_role(user_id=user_id, role_id=role)

        new_roles_ids = list()
        assert rm.add_role('advanced1')
        new_roles_ids.append(rm.get_role(name='advanced1')['id'])
        assert rm.add_role('advanced2')
        new_roles_ids.append(rm.get_role(name='advanced2')['id'])

        position = 1
        for role in new_roles_ids:
            urm.add_role_to_user(user_id=user_id, role_id=role, position=position)
            roles_ids.insert(position, role)
            position += 1

        user_roles = [role.id for role in urm.get_all_roles_from_user(user_id=user_id)]

        assert user_roles == roles_ids


def test_add_role_policy_level(db_setup):
    """Check role-policy relation is added with level to database"""
    with db_setup.RolesPoliciesManager() as rpm:
        with db_setup.PoliciesManager() as pm:
            assert pm.delete_all_policies()
        with db_setup.RolesManager() as rm:
            assert rm.delete_all_roles()

        policies_ids = list()

        with db_setup.RolesManager() as rm:
            rm.add_role('normal')
            role_id = rm.get_role('normal')['id']

        with db_setup.PoliciesManager() as pm:
            policy = {
                'actions': ['agents:update'],
                'resources': [
                    'agent:id:005', 'agent:id:003'
                ],
                'effect': 'allow'
            }
            pm.add_policy('normalPolicy', policy)
            policies_ids.append(pm.get_policy('normalPolicy')['id'])
            policy['actions'] = ['agents:create']
            pm.add_policy('advancedPolicy', policy)
            policies_ids.append(pm.get_policy('advancedPolicy')['id'])

        # New role-policy
        for n_policy in policies_ids:
            rpm.add_role_to_policy(policy_id=n_policy, role_id=role_id)
        for n_policy in policies_ids:
            assert rpm.exist_role_policy(policy_id=n_policy, role_id=role_id)

        new_policies_ids = list()
        policy['actions'] = ['agents:delete']
        pm.add_policy('deletePolicy', policy)
        new_policies_ids.append(pm.get_policy('deletePolicy')['id'])
        policy['actions'] = ['agents:read']
        pm.add_policy('readPolicy', policy)
        new_policies_ids.append(pm.get_policy('readPolicy')['id'])

        position = 1
        for policy in new_policies_ids:
            rpm.add_role_to_policy(policy_id=policy, role_id=role_id, position=position)
            policies_ids.insert(position, policy)
            position += 1

        role_policies = [policy.id for policy in rpm.get_all_policies_from_role(role_id)]

        assert role_policies == policies_ids


def test_exist_user_role(db_setup):
    """Check user-role relation exist in the database"""
    with db_setup.UserRolesManager() as urm:
        user_ids, roles_ids = add_user_roles(db_setup)
        for role in roles_ids:
            for user_id in user_ids:
                with db_setup.AuthenticationManager() as am:
                    assert am.get_user(username='normalUser')
                assert urm.exist_user_role(user_id=user_id, role_id=role)

        assert urm.exist_user_role(user_id='999', role_id=8) == db_setup.SecurityError.USER_NOT_EXIST
        assert urm.exist_user_role(user_id=user_ids[0], role_id=99) == db_setup.SecurityError.ROLE_NOT_EXIST


def test_exist_role_rule(db_setup):
    """Check role-rule relation exist in the database"""
    with db_setup.RolesRulesManager() as rrum:
        role_ids, rule_ids = add_role_rule(db_setup)
        for role in role_ids:
            for rule in rule_ids:
                assert rrum.exist_role_rule(rule_id=rule, role_id=role)

        assert rrum.exist_role_rule(rule_id=999, role_id=role_ids[0]) == db_setup.SecurityError.RULE_NOT_EXIST
        assert rrum.exist_role_rule(rule_id=rule_ids[0], role_id=999) == db_setup.SecurityError.ROLE_NOT_EXIST
        assert not rrum.exist_role_rule(rule_id=rule_ids[0], role_id=1)


def test_exist_policy_role(db_setup):
    """Check role-policy relation exist in the database"""
    with db_setup.RolesPoliciesManager() as rpm:
        policies_ids, roles_ids = add_role_policy(db_setup)
        for policy in policies_ids:
            for role in roles_ids:
                assert rpm.exist_policy_role(policy_id=policy, role_id=role)


def test_exist_role_policy(db_setup):
    """Check role-policy relation exist in the database
    """
    with db_setup.RolesPoliciesManager() as rpm:
        policies_ids, roles_ids = add_role_policy(db_setup)
        for policy in policies_ids:
            for role in roles_ids:
                assert rpm.exist_role_policy(policy_id=policy, role_id=role)

    assert rpm.exist_role_policy(policy_id=policy, role_id=9999) == db_setup.SecurityError.ROLE_NOT_EXIST
    assert rpm.exist_role_policy(policy_id=9999, role_id=roles_ids[0]) == db_setup.SecurityError.POLICY_NOT_EXIST


def test_get_all_roles_from_user(db_setup):
    """Check all roles in one user in the database"""
    with db_setup.UserRolesManager() as urm:
        user_ids, roles_ids = add_user_roles(db_setup)
        for user_id in user_ids:
            roles = urm.get_all_roles_from_user(user_id=user_id)
            for role in roles:
                assert role.id in roles_ids


def test_get_all_rules_from_role(db_setup):
    """Check all rules in one role in the database"""
    with db_setup.RolesRulesManager() as rrum:
        role_ids, rule_ids = add_role_rule(db_setup)
        for rule in rule_ids:
            roles = rrum.get_all_roles_from_rule(rule_id=rule)
            for role in roles:
                assert role.id in role_ids


def test_get_all_roles_from_rule(db_setup):
    """Check all roles in one rule in the database"""
    with db_setup.RolesRulesManager() as rrum:
        role_ids, rule_ids = add_role_rule(db_setup)
        for role in role_ids:
            rules = rrum.get_all_rules_from_role(role_id=role)
            for rule in rules:
                assert rule.id in rule_ids


def test_get_all_users_from_role(db_setup):
    """Check all roles in one user in the database"""
    with db_setup.UserRolesManager() as urm:
        user_id, roles_ids = add_user_roles(db_setup)
        for role in roles_ids:
            users = urm.get_all_users_from_role(role_id=role)
            for user in users:
                assert user['id'] in user_id


def test_get_all_policy_from_role(db_setup):
    """Check all policies in one role in the database"""
    with db_setup.RolesPoliciesManager() as rpm:
        policies_ids, roles_ids = add_role_policy(db_setup)
        for role in roles_ids:
            policies = rpm.get_all_policies_from_role(role_id=role)
            for index, policy in enumerate(policies):
                assert policy.id == policies_ids[index]


def test_get_all_role_from_policy(db_setup):
    """Check all policies in one role in the database"""
    with db_setup.RolesPoliciesManager() as rpm:
        policies_ids, roles_ids = add_role_policy(db_setup)
        for policy in policies_ids:
            roles = [role.id for role in rpm.get_all_roles_from_policy(policy_id=policy)]
            for role_id in roles_ids:
                assert role_id in roles


def test_remove_all_roles_from_user(db_setup):
    """Remove all roles in one user in the database"""
    with db_setup.UserRolesManager() as urm:
        user_ids, roles_ids = add_user_roles(db_setup)
        for user in user_ids:
            urm.remove_all_roles_in_user(user_id=user)
            for index, role in enumerate(roles_ids):
                assert not urm.exist_user_role(role_id=role, user_id=user)


def test_remove_all_users_from_role(db_setup):
    """Remove all roles in one user in the database"""
    with db_setup.UserRolesManager() as urm:
        user_ids, roles_ids = add_user_roles(db_setup)
        for role in roles_ids:
            urm.remove_all_users_in_role(role_id=role)
            for index, user in enumerate(user_ids):
                assert not urm.exist_user_role(role_id=role, user_id=user)


def test_remove_all_rules_from_role(db_setup):
    """Remove all rules in one role in the database"""
    with db_setup.RolesRulesManager() as rrum:
        role_ids, rule_ids = add_role_rule(db_setup)
        for role in role_ids:
            rrum.remove_all_rules_in_role(role_id=role)
        for index, role in enumerate(role_ids):
            assert not rrum.exist_role_rule(role_id=role, rule_id=rule_ids[index])


def test_remove_all_roles_from_rule(db_setup):
    """Remove all roles in one rule in the database"""
    with db_setup.RolesRulesManager() as rrum:
        role_ids, rule_ids = add_role_rule(db_setup)
        no_admin_rules = list()
        for rule in rule_ids:
            if rrum.remove_all_roles_in_rule(rule_id=rule) is True:
                no_admin_rules.append(rule)
        for index, rule in enumerate(no_admin_rules):
            assert not rrum.exist_role_rule(role_id=role_ids[index], rule_id=rule)


def test_remove_all_policies_from_role(db_setup):
    """Remove all policies in one role in the database"""
    with db_setup.RolesPoliciesManager() as rpm:
        policies_ids, roles_ids = add_role_policy(db_setup)
        for role in roles_ids:
            rpm.remove_all_policies_in_role(role_id=role)
        for index, role in enumerate(roles_ids):
            assert not rpm.exist_role_policy(role_id=role, policy_id=policies_ids[index])


def test_remove_all_roles_from_policy(db_setup):
    """Remove all policies in one role in the database"""
    with db_setup.RolesPoliciesManager() as rpm:
        policies_ids, roles_ids = add_role_policy(db_setup)
        for policy in policies_ids:
            rpm.remove_all_roles_in_policy(policy_id=policy)
        for index, policy in enumerate(policies_ids):
            assert not rpm.exist_role_policy(role_id=roles_ids[index], policy_id=policy)


def test_remove_role_from_user(db_setup):
    """Remove specified role in user in the database"""
    with db_setup.UserRolesManager() as urm:
        user_ids, roles_ids = add_user_roles(db_setup)
        for role in roles_ids:
            urm.remove_role_in_user(role_id=role, user_id=user_ids[0])
            assert not urm.exist_user_role(role_id=role, user_id=user_ids[0])


def test_remove_policy_from_role(db_setup):
    """Remove specified policy in role in the database"""
    with db_setup.RolesPoliciesManager() as rpm:
        policies_ids, roles_ids = add_role_policy(db_setup)
        for policy in policies_ids:
            rpm.remove_policy_in_role(role_id=roles_ids[0], policy_id=policy)
        for policy in policies_ids:
            assert not rpm.exist_role_policy(role_id=roles_ids[0], policy_id=policy)


def test_remove_role_from_policy(db_setup):
    """Remove specified role in policy in the database"""
    with db_setup.RolesPoliciesManager() as rpm:
        policies_ids, roles_ids = add_role_policy(db_setup)
        for policy in policies_ids:
            rpm.remove_policy_in_role(role_id=roles_ids[0], policy_id=policy)
        for policy in policies_ids:
            assert not rpm.exist_role_policy(role_id=roles_ids[0], policy_id=policy)


def test_update_role_from_user(db_setup):
    """Replace specified role in user in the database"""
    with db_setup.UserRolesManager() as urm:
        user_ids, roles_ids = add_user_roles(db_setup)
        urm.remove_role_in_user(user_id=user_ids[0], role_id=roles_ids[-1])
        assert urm.replace_user_role(user_id=user_ids[0], actual_role_id=roles_ids[0],
                                     new_role_id=roles_ids[-1]) is True

        assert not urm.exist_user_role(user_id=user_ids[0], role_id=roles_ids[0])
        assert urm.exist_user_role(user_id=user_ids[0], role_id=roles_ids[-1])


def test_update_policy_from_role(db_setup):
    """Replace specified policy in role in the database"""
    with db_setup.RolesPoliciesManager() as rpm:
        policies_ids, roles_ids = add_role_policy(db_setup)
        rpm.remove_policy_in_role(role_id=roles_ids[0], policy_id=policies_ids[-1])
        assert rpm.replace_role_policy(role_id=roles_ids[0], current_policy_id=policies_ids[0],
                                       new_policy_id=policies_ids[-1]) is True

        assert not rpm.exist_role_policy(role_id=roles_ids[0], policy_id=policies_ids[0])
        assert rpm.exist_role_policy(role_id=roles_ids[0], policy_id=policies_ids[-1])


def test_databasemanager___init__(fresh_in_memory_db):
    """Test class constructor for `DatabaseManager`."""
    assert hasattr(fresh_in_memory_db.db_manager, "engines")
    assert hasattr(fresh_in_memory_db.db_manager, "sessions")


@patch("wazuh.rbac.orm.create_engine")
@patch("wazuh.rbac.orm.sessionmaker")
def test_databasemanager_connect(sessionmaker_mock, create_engine_mock, fresh_in_memory_db):
    """Test `connect` method for class `DatabaseManager`."""
    dbm = fresh_in_memory_db.db_manager
    db_path = "/random/path/to/database.db"
    dbm.connect(db_path)

    assert dbm.engines[db_path]
    assert dbm.sessions[db_path]

    sessionmaker_mock.assert_called_once_with(bind=dbm.engines[db_path])
    create_engine_mock.assert_called_once_with(f"sqlite:///{db_path}", echo=False)


@patch("wazuh.rbac.orm.create_engine")
@patch("wazuh.rbac.orm.sessionmaker")
def test_databasemanager_close_sessions(sessionmaker_mock, create_engine_mock, fresh_in_memory_db):
    """Test `close_sessions` method for class `DatabaseManager`."""
    dbm = fresh_in_memory_db.db_manager
    db_path = "/random/path/to/database.db"
    dbm.connect(db_path)

    dbm.close_sessions()

    create_engine_mock.assert_has_calls([call().dispose()])
    sessionmaker_mock.assert_has_calls([call()().close()])


@patch("wazuh.rbac.orm._Base.metadata.create_all")
def test_databasemanager_create_database(create_db_mock, fresh_in_memory_db):
    """Test `create_database` method for class `DatabaseManager`."""
    dbm = fresh_in_memory_db.db_manager
    db_path = "random/path/to_database.db"
    engine_mock = MagicMock()
    dbm.engines = engine_mock

    dbm.create_database(db_path)

    engine_mock.assert_has_calls([call.__getitem__(db_path)])
    create_db_mock.assert_called_once_with(dbm.engines[db_path])


def test_databasemanager_get_database_version(fresh_in_memory_db):
    """Test `get_database_version` method for class `DatabaseManager`."""
    # Assert its version is 0 using the method (value set by default)
    assert fresh_in_memory_db.db_manager.get_database_version(in_memory_db_path) == "0"


def test_databasemanager_insert_default_resources(fresh_in_memory_db):
    """Test `insert_default_resources` method for class `DatabaseManager`.

    Only a brief check of the number of default security resources added will be tested.
    """

    def _get_default_resources(resource: str) -> dict:
        with open(os.path.join(default_path, f"{resource}.yaml"), 'r') as r_stream:
            return yaml.safe_load(r_stream)

    # Insert default resources
    fresh_in_memory_db.db_manager.insert_default_resources(in_memory_db_path)
    default_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'default')

    # Check default users
    default_users = _get_default_resources("users")
    with fresh_in_memory_db.AuthenticationManager(fresh_in_memory_db.db_manager.sessions[in_memory_db_path]) as auth:
        users = auth.get_users()
        assert len([user for user in users if user['user_id'] < fresh_in_memory_db.MAX_ID_RESERVED]) \
               == len(default_users[next(iter(default_users))])

    # Check default roles
    default_roles = _get_default_resources("roles")
    with fresh_in_memory_db.RolesManager(fresh_in_memory_db.db_manager.sessions[in_memory_db_path]) as rm:
        roles = rm.get_roles()
        assert len([role for role in roles if role.id < fresh_in_memory_db.MAX_ID_RESERVED]) \
               == len(default_roles[next(iter(default_roles))])

    # Check default policies
    default_policies = [policy for policy_group in _get_default_resources("policies")['default_policies'].values()
                        for policy in policy_group['policies']]

    with fresh_in_memory_db.PoliciesManager(fresh_in_memory_db.db_manager.sessions[in_memory_db_path]) as pm:
        policies = pm.get_policies()
        assert len([policy for policy in policies if policy.id < fresh_in_memory_db.MAX_ID_RESERVED]) \
               == len(default_policies)

    # Check default rules
    default_rules = _get_default_resources("rules")
    with fresh_in_memory_db.RulesManager(fresh_in_memory_db.db_manager.sessions[in_memory_db_path]) as rum:
        rules = rum.get_rules()
        assert len([rule for rule in rules if rule.id < fresh_in_memory_db.MAX_ID_RESERVED]) \
               == len(default_rules[next(iter(default_rules))])


def test_databasemanager_get_table(fresh_in_memory_db):
    """Test `get_table` method for class `DatabaseManager`."""

    class EnhancedUser(fresh_in_memory_db.User):
        new_column = Column("new_column", String(32), nullable=False, default="default_value")

        def __init__(self, new_column=None):
            self.new_column = new_column

    session = fresh_in_memory_db.db_manager.sessions[in_memory_db_path]
    column_regex = r"users\.([a-z_]+)"

    # Assert that `get_table` returns the correct Query object depending on the given Table
    current_columns = set(re.findall(column_regex, str(fresh_in_memory_db.db_manager.get_table(
        session, fresh_in_memory_db.User))))
    with patch("wazuh.rbac.orm._new_columns", new={"new_column"}):
        updated_columns = set(re.findall(column_regex, str(fresh_in_memory_db.db_manager.get_table(session,
                                                                                                   EnhancedUser))))

    assert current_columns == updated_columns

    # Assert that `get_table` uses `_new_columns` correctly. Thus, if the new column is not added to that set, an
    # exception will raise
    with pytest.raises(OperationalError):
        fresh_in_memory_db.db_manager.get_table(session, EnhancedUser).first()


def test_databasemanager_rollback(fresh_in_memory_db):
    """Test `rollback` method for class `DatabaseManager`."""
    fresh_in_memory_db.db_manager.sessions[in_memory_db_path] = MagicMock()
    fresh_in_memory_db.db_manager.rollback(in_memory_db_path)
    fresh_in_memory_db.db_manager.sessions[in_memory_db_path].assert_has_calls([call.rollback()])


def test_databasemanager_set_database_version(fresh_in_memory_db):
    """Test `set_database_version` method for class `DatabaseManager`."""
    fresh_in_memory_db.db_manager.set_database_version(in_memory_db_path, 555)
    assert fresh_in_memory_db.db_manager.sessions[in_memory_db_path].execute(text("pragma user_version")).first()[0] == 555


@patch("wazuh.rbac.orm.safe_move")
@patch("wazuh.rbac.orm.os.remove")
@patch("wazuh.rbac.orm.chown")
@patch("wazuh.rbac.orm.os.chmod")
def test_check_database_integrity(chmod_mock, chown_mock, remove_mock, safe_move_mock, fresh_in_memory_db):
    """Test `check_database_integrity` function briefly.

    NOTE: To correctly test this procedure, use the RBAC database migration integration tests.
    """
    db_mock = MagicMock()
    with patch("wazuh.rbac.orm.db_manager", new=db_mock):
        with patch("wazuh.rbac.orm.os.path.exists", return_value=True):
            with patch("wazuh.rbac.orm.CURRENT_ORM_VERSION", new=99999):
                # DB exists and a migration is needed
                fresh_in_memory_db.check_database_integrity()
                db_mock.assert_has_calls([
                    call.connect(fresh_in_memory_db.DB_FILE_TMP),
                    call.get_database_version(fresh_in_memory_db.DB_FILE),
                    call.create_database(fresh_in_memory_db.DB_FILE_TMP),
                    call.insert_default_resources(fresh_in_memory_db.DB_FILE_TMP),
                    call.migrate_data(source=fresh_in_memory_db.DB_FILE, target=fresh_in_memory_db.DB_FILE_TMP,
                                      from_id=fresh_in_memory_db.WAZUH_USER_ID,
                                      to_id=fresh_in_memory_db.WAZUH_WUI_USER_ID),
                    call.migrate_data(source=fresh_in_memory_db.DB_FILE, target=fresh_in_memory_db.DB_FILE_TMP,
                                      from_id=fresh_in_memory_db.CLOUD_RESERVED_RANGE,
                                      to_id=fresh_in_memory_db.MAX_ID_RESERVED),
                    call.migrate_data(source=fresh_in_memory_db.DB_FILE, target=fresh_in_memory_db.DB_FILE_TMP,
                                      from_id=fresh_in_memory_db.MAX_ID_RESERVED + 1),
                    call.set_database_version(fresh_in_memory_db.DB_FILE_TMP, fresh_in_memory_db.CURRENT_ORM_VERSION),
                    call.close_sessions()
                ], any_order=True)

        safe_move_mock.assert_called_once_with(fresh_in_memory_db.DB_FILE_TMP, fresh_in_memory_db.DB_FILE,
                                               ownership=(fresh_in_memory_db.wazuh_uid(),
                                                          fresh_in_memory_db.wazuh_gid()),
                                               permissions=0o640)

        # DB does not exist. A new one will be initialized
        fresh_in_memory_db.check_database_integrity()
        db_mock.assert_has_calls([
            call.connect(fresh_in_memory_db.DB_FILE),
            call.create_database(fresh_in_memory_db.DB_FILE),
            call.insert_default_resources(fresh_in_memory_db.DB_FILE),
            call.set_database_version(fresh_in_memory_db.DB_FILE, fresh_in_memory_db.CURRENT_ORM_VERSION),
            call.close_sessions()
        ], any_order=True)


@pytest.mark.parametrize("exception", [ValueError, Exception])
@patch("wazuh.rbac.orm.DatabaseManager.close_sessions")
@patch("wazuh.rbac.orm.os.remove")
def test_check_database_integrity_exceptions(remove_mock, close_sessions_mock, exception, fresh_in_memory_db):
    """Test `check_database_integrity` function exceptions briefly.

    NOTE: To correctly test this procedure, use the RBAC database migration integration tests.
    """

    def mocked_exists(path: str):
        return path == fresh_in_memory_db.DB_FILE_TMP

    with patch("wazuh.rbac.orm.os.path.exists", side_effect=mocked_exists) as mock_exists:
        with patch("wazuh.rbac.orm.DatabaseManager.connect", side_effect=exception) as db_manager_mock:
            with pytest.raises(exception):
                fresh_in_memory_db.check_database_integrity()

            close_sessions_mock.assert_called_once()
            mock_exists.assert_called_with(fresh_in_memory_db.DB_FILE_TMP)
            remove_mock.assert_called_with(fresh_in_memory_db.DB_FILE_TMP)


@pytest.mark.parametrize('from_id, to_id, users', [
    (WAZUH_USER_ID, WAZUH_WUI_USER_ID, [
        User('wazuh', 'test', user_id=WAZUH_USER_ID),
        User('wazuh-wui', 'test2', user_id=WAZUH_WUI_USER_ID)
    ]),
    (MAX_ID_RESERVED + 1, None, [
        User('custom', 'test', user_id=110),
        User('custom', 'test', user_id=101)
    ])
])
def test_migrate_data(db_setup, from_id, to_id, users):
    """Test `migrate_data` function briefly.

    NOTE: To correctly test this procedure, use the RBAC database migration integration tests.
    """
    # This test case updates the default user passwords and omits the rest of the migration
    if to_id == WAZUH_WUI_USER_ID:
        with patch("wazuh.rbac.orm.db_manager.get_data", return_value=users):
            with patch("wazuh.rbac.orm.AuthenticationManager.update_user") as mock_update_user:
                db_setup.db_manager.migrate_data(source=db_setup.DB_FILE, target=db_setup.DB_FILE,
                                                 from_id=from_id, to_id=to_id)

                mock_update_user.assert_has_calls([
                    call.update_user(users[0].id, users[0].password, hashed_password=True),
                    call.update_user(users[1].id, users[1].password, hashed_password=True),
                ])
    else:
        # Represents empty items to skip custom rules, policies and roles migration,
        # since they do not depend on the users being migrated
        empty_list = []
        user_exists = False
        with patch("wazuh.rbac.orm.AuthenticationManager.add_user",
                   side_effect=[not user_exists, user_exists, not user_exists]) as mock_add_user:
            with patch("wazuh.rbac.orm.db_manager.get_data",
                       side_effect=[users, empty_list, empty_list, empty_list, empty_list, empty_list, empty_list]):
                db_setup.db_manager.migrate_data(source=db_setup.DB_FILE, target=db_setup.DB_FILE,
                                                 from_id=from_id, to_id=to_id)
                user1 = users[0]
                user2 = users[1]

                mock_add_user.assert_has_calls([
                    call.add_user(
                        username=user1.username, password=user1.password, created_at=user1.created_at, user_id=user1.id,
                        hashed_password=True, check_default=False,
                    ),
                    call.add_user(
                        username=user2.username, password=user2.password, created_at=user2.created_at, user_id=user2.id,
                        hashed_password=True, check_default=False,
                    ),
                    call.add_user(
                        username=f"{user2.username}_user", password=user2.password, created_at=user2.created_at,
                        user_id=user2.id, hashed_password=True, check_default=False,
                    ),
                ])


@pytest.mark.parametrize('user_data',
                         [
                             {'user': User('wazuh', 'test', user_id=WAZUH_USER_ID), 'status': True,
                              'expected_update': True},
                             {'user': User('wazuh', 'test', user_id=WAZUH_WUI_USER_ID), 'status': True,
                              'expected_update': True},
                             {'user': User('wazuh', 'test', user_id=110), 'status': True,
                              'expected_update': False},
                             {'user': User('wazuh', 'test', user_id=101), 'status': False,
                              'expected_update': False},
                         ]
                         )
def test_authentication_manager_migrate_data(db_setup, user_data):
    """Test migrate_data method for the AuthenticationManager class."""
    user = user_data['user']
    expected_update = user_data['expected_update']
    status = user_data['status']

    with db_setup.AuthenticationManager() as auth_manager:
        with patch("wazuh.rbac.orm.db_manager.get_data", return_value=[user]):
            with patch("wazuh.rbac.orm.AuthenticationManager.update_user") as mock_update_user:
                with patch("wazuh.rbac.orm.AuthenticationManager.add_user",
                           side_effect=[status, status]) as mock_add_user:
                    auth_manager.migrate_data(db_setup.db_manager, source=db_setup.DB_FILE, target=db_setup.DB_FILE,
                                              from_id='someId', to_id='otherId')

                    if expected_update:
                        mock_update_user.assert_has_calls(
                            [call.update_user(user.id, user.password, hashed_password=True)])
                    else:
                        expected_calls = [call.add_user(username=user.username, password=user.password,
                                                        created_at=user.created_at, user_id=user.id,
                                                        hashed_password=True, check_default=False)]
                        if status is False:
                            expected_calls = expected_calls + [
                                call.add_user(username=f"{user.username}_user", password=user.password,
                                              created_at=user.created_at, user_id=user.id,
                                              hashed_password=True, check_default=False)]

                        mock_add_user.assert_has_calls(expected_calls)


@pytest.mark.parametrize('role_data',
                         [
                             {'user': Roles(WAZUH_USER_ID, 'wazuh'), 'status': True},
                             {'user': Roles(WAZUH_WUI_USER_ID, 'wazuh'), 'status': True},
                             {'user': Roles(110, 'wazuh'), 'status': True},
                             {'user': Roles(101, 'wazuh'), 'status': SecurityError.ALREADY_EXIST},
                         ]
                         )
def test_roles_manager_migrate_data(db_setup, role_data):
    """Test migrate_data method for the RolesManager class."""
    role = role_data['user']
    status = role_data['status']

    with db_setup.RolesManager() as role_manager:
        with patch("wazuh.rbac.orm.db_manager.get_data", return_value=[role]):
            with patch("wazuh.rbac.orm.RolesManager.add_role",
                       side_effect=[status, status]) as mock_add_role:
                role_manager.migrate_data(db_setup.db_manager, source=db_setup.DB_FILE, target=db_setup.DB_FILE,
                                          from_id='someId', to_id='otherId')

                expected_calls = [call.add_role(name=role.name,
                                                created_at=role.created_at, role_id=role.id,
                                                check_default=False)]
                if status == SecurityError.ALREADY_EXIST:
                    expected_calls = expected_calls + [
                        call.add_role(name=f"{role.name}_user",
                                      created_at=role.created_at, role_id=role.id,
                                      check_default=False)]

                mock_add_role.assert_has_calls(expected_calls)


def test_roles_manager_migrate_data_with_reserved_ids(db_setup):
    """Test migrate_data method with reserved ids for the RolesManager class."""
    role = Roles(WAZUH_USER_ID, 'wazuh')

    with db_setup.RolesManager() as role_manager:
        with patch("wazuh.rbac.orm.db_manager.get_data", return_value=[role]):
            with patch("wazuh.rbac.orm.RolesManager.add_role") as mock_add_role:
                role_manager.migrate_data(db_setup.db_manager, source=db_setup.DB_FILE, target=db_setup.DB_FILE,
                                          from_id=WAZUH_USER_ID, to_id=WAZUH_WUI_USER_ID)

                mock_add_role.assert_not_called()


@pytest.mark.parametrize('rules_data',
                         [
                             {'rules': Rules("example_name", '{}', 1001), 'status': True},
                             {'rules': Rules("example_name", '{}', 1001), 'status': SecurityError.ALREADY_EXIST},
                         ]
                         )
def test_rules_manager_migrate_data(db_setup, rules_data):
    """Test migrate_data method for the RulesManager class."""
    rule = rules_data['rules']
    status = rules_data['status']

    # Mock RolesRules object
    mock_roles_rules = MagicMock()
    mock_roles_rules.rule_id = rule.id
    mock_roles_rules.id = 1
    mock_roles_rules.created_at = None

    with db_setup.RulesManager() as rule_manager:
        with patch("wazuh.rbac.orm.db_manager.get_data", return_value=[rule]):
            with patch('wazuh.rbac.orm.db_manager.sessions', autospec=True) as mock_sessions:
                with patch("wazuh.rbac.orm.RulesManager.add_rule", side_effect=[status, status]) as mock_add_rule:
                    with patch("wazuh.rbac.orm.db_manager.get_table") as mock_get_table:
                        with patch("wazuh.rbac.orm.RolesRulesManager.add_rule_to_role") as mock_add_rule_to_role:
                            # Mock get_table to return a list of mocked RolesRules objects
                            mock_get_table.return_value.filter.return_value.order_by.return_value.all.return_value = [
                                mock_roles_rules]
                            # Mock the manager session
                            mock_query = mock_sessions.return_value.query.return_value
                            mock_filter_by = mock_query.filter_by.return_value
                            mock_first = mock_filter_by.first.return_value
                            mock_first.id = rule.id

                            rule_manager.migrate_data(db_setup.db_manager, source=db_setup.DB_FILE, target=db_setup.DB_FILE,
                                                      from_id='someId', to_id='otherId')

                            expected_calls = [call.add_rule(name=rule.name, rule=json.loads(rule.rule),
                                                            created_at=rule.created_at,
                                                            rule_id=rule.id, check_default=False)]

                            if status == SecurityError.ALREADY_EXIST:
                                mock_add_rule_to_role.assert_called()

                            mock_add_rule.assert_has_calls(expected_calls)


def test_rules_manager_migrate_data_with_reserved_ids(db_setup):
    """Test migrate_data method with reserved ids for the RulesManager class."""
    rule = Rules("example_name", '{}', 1001)

    with db_setup.RulesManager() as rule_manager:
        with patch("wazuh.rbac.orm.db_manager.get_data", return_value=[rule]):
            with patch("wazuh.rbac.orm.RulesManager.add_rule") as mock_add_rule:
                rule_manager.migrate_data(db_setup.db_manager, source=db_setup.DB_FILE, target=db_setup.DB_FILE,
                                          from_id=WAZUH_USER_ID, to_id=WAZUH_WUI_USER_ID)

                mock_add_rule.assert_not_called()


@pytest.mark.parametrize('policy_data',
                         [
                             {'policy': Policies('wazuh', '{}', policy_id=WAZUH_USER_ID), 'status': True},
                             {'policy': Policies('wazuh', '{}', policy_id=WAZUH_USER_ID),
                              'status': SecurityError.ALREADY_EXIST},
                         ]
                         )
def test_policies_manager_migrate_data(db_setup, policy_data):
    """Test migrate_data method for the PoliciesManager class."""
    policy = policy_data['policy']
    status = policy_data['status']

    with db_setup.PoliciesManager() as policy_manager:
        with patch("wazuh.rbac.orm.db_manager.get_data", return_value=[policy]):
            with patch('wazuh.rbac.orm.db_manager.sessions', autospec=True) as mock_sessions:
                with patch("wazuh.rbac.orm.db_manager.get_table") as mock_get_table:
                    mock_query = mock_sessions.return_value.query.return_value
                    mock_filter_by = mock_query.filter_by.return_value
                    mock_first = mock_filter_by.first.return_value
                    mock_first.id = 'id'
                    with patch("wazuh.rbac.orm.PoliciesManager.add_policy",
                               side_effect=[status, status]) as mock_add_policy:
                        policy_manager.migrate_data(db_setup.db_manager, source=db_setup.DB_FILE,
                                                    target=db_setup.DB_FILE,
                                                    from_id='someId', to_id='otherId')

                        expected_calls = [call.add_role(name=policy.name, policy=json.loads(policy.policy),
                                                        created_at=policy.created_at, policy_id=policy.id,
                                                        check_default=False)]
                        mock_add_policy.assert_has_calls(expected_calls)
                        if status == SecurityError.ALREADY_EXIST:
                            mock_get_table.assert_called()


def test_policies_manager_migrate_data_with_reserved_ids(db_setup):
    """Test migrate_data method with reserved ids for the PoliciesManager class."""
    policy = Policies('wazuh', 'some_policy')

    with db_setup.PoliciesManager() as policy_manager:
        with patch("wazuh.rbac.orm.db_manager.get_data", return_value=[policy]):
            with patch("wazuh.rbac.orm.PoliciesManager.add_policy") as mock_add_policy:
                policy_manager.migrate_data(db_setup.db_manager, source=db_setup.DB_FILE, target=db_setup.DB_FILE,
                                            from_id=WAZUH_USER_ID, to_id=WAZUH_WUI_USER_ID)

                mock_add_policy.assert_not_called()


@pytest.mark.parametrize('user_role_data',
                         [
                             MockedUserRole('2', '3', 'someDate', 1),
                             MockedUserRole(MAX_ID_RESERVED, '3', 'someDate', 2),
                             MockedUserRole('3', MAX_ID_RESERVED, 'someDate', 3),
                             MockedUserRole(MAX_ID_RESERVED, MAX_ID_RESERVED, 'someDate', 4)
                         ])
def test_user_roles_manager_migrate_data(db_setup, user_role_data):
    """Test migrate_data method for the UserRolesManager class."""
    user_role = user_role_data
    role_id = user_role_data.role_id
    user_id = user_role_data.user_id

    with db_setup.UserRolesManager() as user_roles_manager:
        with patch("wazuh.rbac.orm.db_manager.get_data", return_value=[user_role]):
            with patch("wazuh.rbac.orm.UserRolesManager.add_role_to_user") as mock_add_role_to_user:
                with patch('wazuh.rbac.orm.AuthenticationManager.get_user', autospec=True,
                           return_value={'id': None}) as mock_get_user:
                    with patch('wazuh.rbac.orm.RolesManager.get_role', autospec=True,
                               return_value={'id': None}) as mock_get_role:
                        with patch("wazuh.rbac.orm.db_manager.get_table") as mock_get_table:
                            mock_filter_by = mock_get_table.return_value.filter.return_value
                            mock_first = mock_filter_by.first.return_value
                            mock_first.username = 'username'
                            mock_first.user = 'user'

                            user_roles_manager.migrate_data(db_setup.db_manager, source=db_setup.DB_FILE,
                                                            target=db_setup.DB_FILE,
                                                            from_id='1', to_id='2')

                            if int(user_id) <= MAX_ID_RESERVED:
                                mock_get_user.assert_called()

                            if int(role_id) <= MAX_ID_RESERVED:
                                mock_get_role.assert_called()

                            mock_add_role_to_user.assert_called()


def test_user_roles_manager_migrate_data_with_reserved_ids(db_setup):
    """Test migrate_data method with reserved ids for the UserRolesManager class."""
    user_role = UserRoles()

    with db_setup.UserRolesManager() as user_roles_manager:
        with patch("wazuh.rbac.orm.db_manager.get_data", return_value=[user_role]):
            with patch("wazuh.rbac.orm.UserRolesManager.add_role_to_user") as mock_add_role_to_user:
                user_roles_manager.migrate_data(db_setup.db_manager, source=db_setup.DB_FILE, target=db_setup.DB_FILE,
                                                from_id=WAZUH_USER_ID, to_id=WAZUH_WUI_USER_ID)

                mock_add_role_to_user.assert_not_called()


@pytest.mark.parametrize('role_policies_data',
                         [
                             MockRolePolicy('2', '3', 'someDate', 1),
                             MockRolePolicy(MAX_ID_RESERVED, '3', 'someDate', 2),
                             MockRolePolicy('3', MAX_ID_RESERVED, 'someDate', 3),
                             MockRolePolicy(MAX_ID_RESERVED, MAX_ID_RESERVED, 'someDate', 4)
                         ]
                         )
def test_roles_policies_manager_migrate_data(db_setup, role_policies_data):
    """Test migrate_data method for the RolesPoliciesManager class."""
    role_policies = role_policies_data
    role_id = role_policies.role_id
    policy_id = role_policies.policy_id

    with db_setup.RolesPoliciesManager() as auth_manager:
        with patch("wazuh.rbac.orm.db_manager.get_data", return_value=[role_policies]):
            with patch("wazuh.rbac.orm.RolesPoliciesManager.add_policy_to_role") as mock_add_policy_to_role:
                with patch('wazuh.rbac.orm.PoliciesManager.get_policy', autospec=True,
                           return_value={'id': None}) as mock_get_policy:
                    with patch('wazuh.rbac.orm.RolesManager.get_role', autospec=True,
                               return_value={'id': None}) as mock_get_role:
                        with patch("wazuh.rbac.orm.db_manager.get_table") as mock_get_table:
                            mock_filter_by = mock_get_table.return_value.filter.return_value
                            mock_first = mock_filter_by.first.return_value
                            mock_first.name = 'name'

                            auth_manager.migrate_data(db_setup.db_manager, source=db_setup.DB_FILE,
                                                      target=db_setup.DB_FILE,
                                                      from_id='1', to_id='2')

                            if int(policy_id) <= MAX_ID_RESERVED:
                                mock_get_policy.assert_called()

                            if int(role_id) <= MAX_ID_RESERVED:
                                mock_get_role.assert_called()

                            mock_add_policy_to_role.assert_called()


def test_roles_policies_manager_migrate_data_with_reserved_ids(db_setup):
    """Test migrate_data method with reserved ids for the RolesPoliciesManager class."""
    user_role = RolesPolicies()

    with db_setup.RolesPoliciesManager() as role_policies_manager:
        with patch("wazuh.rbac.orm.db_manager.get_data", return_value=[user_role]):
            with patch("wazuh.rbac.orm.RolesPoliciesManager.add_policy_to_role") as mock_add_policy_to_role:
                role_policies_manager.migrate_data(db_setup.db_manager, source=db_setup.DB_FILE,
                                                   target=db_setup.DB_FILE,
                                                   from_id=WAZUH_USER_ID, to_id=WAZUH_WUI_USER_ID)

                mock_add_policy_to_role.assert_not_called()


@pytest.mark.parametrize('role_rules_data',
                         [
                             MockRoleRules('2', '3', 'someDate', 1),
                             MockRoleRules(MAX_ID_RESERVED, '3', 'someDate', 2),
                             MockRoleRules('3', MAX_ID_RESERVED, 'someDate', 3),
                             MockRoleRules(MAX_ID_RESERVED, MAX_ID_RESERVED, 'someDate', 4)
                         ]
                         )
def test_roles_rules_manager_migrate_data(db_setup, role_rules_data):
    """Test migrate_data method for the RolesRulesManager class."""
    role_rules = role_rules_data
    role_id = role_rules.role_id
    rule_id = role_rules.rule_id

    with db_setup.RolesRulesManager() as roles_rules_manager:
        with patch("wazuh.rbac.orm.db_manager.get_data", return_value=[role_rules]):
            with patch("wazuh.rbac.orm.RolesRulesManager.add_rule_to_role") as mock_add_rule_to_role:
                with patch('wazuh.rbac.orm.RulesManager.get_rule_by_name', autospec=True,
                           return_value={'id': None}) as mock_get_rule_by_name:
                    with patch('wazuh.rbac.orm.RolesManager.get_role', autospec=True,
                               return_value={'id': None}) as mock_get_role:
                        with patch("wazuh.rbac.orm.db_manager.get_table") as mock_get_table:
                            mock_filter_by = mock_get_table.return_value.filter.return_value
                            mock_first = mock_filter_by.first.return_value
                            mock_first.name = 'name'

                            roles_rules_manager.migrate_data(db_setup.db_manager, source=db_setup.DB_FILE,
                                                             target=db_setup.DB_FILE,
                                                             from_id='1', to_id='2')

                            if int(rule_id) <= MAX_ID_RESERVED:
                                mock_get_rule_by_name.assert_called()

                            if int(role_id) <= MAX_ID_RESERVED:
                                mock_get_role.assert_called()

                            mock_add_rule_to_role.assert_called()


def test_roles_rules_manager_migrate_data_with_reserved_ids(db_setup):
    """Test migrate_data method with reserved ids for the RolesRulesManager class."""
    user_role = RolesRules()

    with db_setup.RolesRulesManager() as roles_rules_manager:
        with patch("wazuh.rbac.orm.db_manager.get_data", return_value=[user_role]):
            with patch("wazuh.rbac.orm.RolesRulesManager.add_rule_to_role") as mock_add_rule_to_role:
                roles_rules_manager.migrate_data(db_setup.db_manager, source=db_setup.DB_FILE,
                                                 target=db_setup.DB_FILE,
                                                 from_id=WAZUH_USER_ID, to_id=WAZUH_WUI_USER_ID)

                mock_add_rule_to_role.assert_not_called()
