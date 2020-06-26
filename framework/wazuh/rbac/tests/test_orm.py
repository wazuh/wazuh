# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import os
from time import time
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine

from wazuh.rbac.tests.utils import init_db

test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data')


@pytest.fixture(scope='function')
def db_setup():
    with patch('wazuh.common.ossec_uid'), patch('wazuh.common.ossec_gid'):
        with patch('sqlalchemy.create_engine', return_value=create_engine("sqlite://")):
            with patch('shutil.chown'), patch('os.chmod'):
                with patch('api.constants.SECURITY_PATH', new=test_data_path):
                    import wazuh.rbac.orm as rbac
    init_db('schema_security_test.sql', test_data_path)

    yield rbac


def test_database_init(db_setup):
    """Check users db is properly initialized"""
    with db_setup.RolesManager() as rm:
        assert rm.get_role('wazuh') != db_setup.SecurityError.ROLE_NOT_EXIST


def test_json_validator(db_setup):
    assert not db_setup.json_validator('Not a dictionary')


def test_add_token(db_setup):
    """Check token rule is added to database"""
    with db_setup.TokenManager() as tm:
        users = {'newUser', 'newUser1'}
        with db_setup.AuthenticationManager() as am:
            for user in users:
                am.add_user(username=user, password='testingA1!')
        # New token rule
        assert tm.add_user_rules(users=users) != db_setup.SecurityError.ALREADY_EXIST

    return users


def test_get_all_token_rules(db_setup):
    """Check that rules are correctly created"""
    users = test_add_token(db_setup)
    with db_setup.TokenManager() as tm:
        rules = tm.get_all_rules()
        for user in rules.keys():
            assert user in users


def test_nbf_invalid(db_setup):
    """Check if a user's token is valid by comparing the values with those stored in the database"""
    current_timestamp = int(time())
    users = test_add_token(db_setup)
    with db_setup.TokenManager() as tm:
        for user in users:
            assert not tm.is_token_valid(username=user, token_nbf_time=current_timestamp)


def test_delete_all_rules(db_setup):
    """Check that rules are correctly deleted"""
    test_add_token(db_setup)
    with db_setup.TokenManager() as tm:
        assert tm.delete_all_rules()


def test_delete_all_expired_rules(db_setup):
    """Check that rules are correctly deleted"""
    with patch('wazuh.rbac.orm.time', return_value=0):
        test_add_token(db_setup)
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
        rm.add_role('newRole', {'Unittest': 'Role'})
        assert rm.get_role('newRole')
        # New role
        rm.add_role('newRole1', {'Unittest1': 'Role'})
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


def test_get_user(db_setup):
    """Check users in the database"""
    with db_setup.AuthenticationManager() as am:
        users = am.get_users()
        assert users
        for user in users:
            assert isinstance(user['username'], str)

        assert users[0]['username'] == 'wazuh'


def test_get_roles(db_setup):
    """Check roles in the database"""
    with db_setup.RolesManager() as rm:
        roles = rm.get_roles()
        assert roles
        for rol in roles:
            assert isinstance(rol.name, str)
            assert isinstance(json.loads(rol.rule), dict)

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


def test_delete_users(db_setup):
    """Check delete users in the database"""
    with db_setup.AuthenticationManager() as am:
        am.add_user(username='toDelete', password='testingA3!')
        len_users = len(am.get_users())
        am.delete_user(username='toDelete')
        assert len_users == len(am.get_users()) + 1


def test_delete_roles(db_setup):
    """Check delete roles in the database"""
    with db_setup.RolesManager() as rm:
        rm.add_role(name='toDelete', rule={'Unittest': 'Role'})
        len_roles = len(rm.get_roles())
        assert rm.delete_role_by_name(role_name='toDelete')
        assert len_roles == len(rm.get_roles()) + 1


def test_delete_all_roles(db_setup):
    """Check delete roles in the database"""
    with db_setup.RolesManager() as rm:
        assert rm.delete_all_roles()
        rm.add_role(name='toDelete', rule={'Unittest': 'Role'})
        rm.add_role(name='toDelete1', rule={'Unittest1': 'Role'})
        len_roles = len(rm.get_roles())
        assert rm.delete_all_roles()
        assert len_roles == len(rm.get_roles()) + 2


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


def test_update_user(db_setup):
    """Check update a user in the database"""
    with db_setup.AuthenticationManager() as am:
        am.add_user(username='toUpdate', password='testingA6!')
        assert am.update_user(username='toUpdate', password='testingA0!')
        assert not am.update_user(username='notexist', password='testingA0!')


def test_update_role(db_setup):
    """Check update a role in the database"""
    with db_setup.RolesManager() as rm:
        rm.add_role(name='toUpdate', rule={'Unittest': 'Role'})
        tid = rm.get_role_id(role_id=106)['id']
        tname = rm.get_role(name='toUpdate')['name']
        rm.update_role(role_id=tid, name='updatedName', rule={'Unittest1': 'Role'})
        assert tid == rm.get_role(name='updatedName')['id']
        assert tname == 'toUpdate'
        assert rm.get_role(name='updatedName')['name'] == 'updatedName'


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


def test_add_policy_role(db_setup):
    """Check role-policy relation is added to database"""
    with db_setup.RolesPoliciesManager() as rpm:
        with db_setup.PoliciesManager() as pm:
            assert pm.delete_all_policies()
        with db_setup.RolesManager() as rm:
            assert rm.delete_all_roles()

        policies_ids = list()
        roles_ids = list()

        with db_setup.RolesManager() as rm:
            rm.add_role(name='normal', rule={'Unittest': 'Role'})
            roles_ids.append(rm.get_role('normal')['id'])
            rm.add_role(name='advanced', rule={'Unittest1': 'Role'})
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


def test_add_user_roles(db_setup):
    """Check user-roles relation is added to database"""
    with db_setup.UserRolesManager() as urm:
        with db_setup.AuthenticationManager() as am:
            for user in am.get_users():
                assert am.delete_user(username=user['username'])
        with db_setup.RolesManager() as rm:
            assert rm.delete_all_roles()

        user_list = list()
        roles_ids = list()

        with db_setup.AuthenticationManager() as am:
            assert am.add_user(username='normalUser', password='testingA1!')
            user_list.append(am.get_user('normalUser')['username'])
            assert am.add_user(username='normalUser1', password='testingA1!')
            user_list.append(am.get_user('normalUser1')['username'])

        with db_setup.RolesManager() as rm:
            assert rm.add_role('normal', rule={'Unittest': 'Role'})
            roles_ids.append(rm.get_role('normal')['id'])
            assert rm.add_role('advanced', rule={'Unittest1': 'Role'})
            roles_ids.append(rm.get_role('advanced')['id'])

        # New user-role
        for role in roles_ids:
            assert urm.add_role_to_user(username='normalUser', role_id=role)
            assert urm.add_user_to_role(username='normalUser1', role_id=role)
        for role in roles_ids:
            assert urm.exist_user_role(username='normalUser', role_id=role)
            assert urm.exist_role_user(username='normalUser', role_id=role)

        return user_list, roles_ids


def test_add_role_policy(db_setup):
    """Check role-policy relation is added to database"""
    with db_setup.RolesPoliciesManager() as rpm:
        with db_setup.PoliciesManager() as pm:
            assert pm.delete_all_policies()
        with db_setup.RolesManager() as rm:
            assert rm.delete_all_roles()

        policies_ids = list()
        roles_ids = list()

        with db_setup.RolesManager() as rm:
            rm.add_role('normalUnit', rule={'Unittest': 'Role'})
            roles_ids.append(rm.get_role('normalUnit')['id'])
            rm.add_role('advancedUnit', rule={'Unittest1': 'Role'})
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
                assert am.delete_user(username=user['username'])
        with db_setup.RolesManager() as rm:
            assert rm.delete_all_roles()

        roles_ids = list()

        with db_setup.AuthenticationManager() as am:
            assert am.add_user(username='normal_level', password='testingA1!')
            username = am.get_user(username='normal_level')['username']

        with db_setup.RolesManager() as rm:
            assert rm.add_role('normal', rule={'Unittest': 'Role'})
            roles_ids.append(rm.get_role('normal')['id'])
            assert rm.add_role('advanced', rule={'Unittest1': 'Role'})
            roles_ids.append(rm.get_role('advanced')['id'])

        # New role-policy
        for role in roles_ids:
            urm.add_role_to_user(username=username, role_id=role)
        for role in roles_ids:
            assert urm.exist_user_role(username=username, role_id=role)

        new_roles_ids = list()
        assert rm.add_role('advanced1', rule={'Unittest2': 'Role'})
        new_roles_ids.append(rm.get_role(name='advanced1')['id'])
        assert rm.add_role('advanced2', rule={'Unittest3': 'Role'})
        new_roles_ids.append(rm.get_role(name='advanced2')['id'])

        position = 1
        for role in new_roles_ids:
            urm.add_role_to_user(username=username, role_id=role, position=position)
            roles_ids.insert(position, role)
            position += 1

        user_roles = [role.id for role in urm.get_all_roles_from_user(username=username)]

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
            rm.add_role('normal', rule={'Unittest': 'Role'})
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
        username_list, roles_ids = test_add_user_roles(db_setup)
        for role in roles_ids:
            for username in username_list:
                assert urm.exist_user_role(username=username, role_id=role)
                assert urm.exist_role_user(username=username, role_id=role)

        assert urm.exist_user_role(username='noexist', role_id=8) == db_setup.SecurityError.USER_NOT_EXIST
        assert urm.exist_user_role(username=username_list[0], role_id=99) == db_setup.SecurityError.ROLE_NOT_EXIST


def test_exist_policy_role(db_setup):
    """Check role-policy relation exist in the database"""
    with db_setup.RolesPoliciesManager() as rpm:
        policies_ids, roles_ids = test_add_role_policy(db_setup)
        for policy in policies_ids:
            for role in roles_ids:
                assert rpm.exist_policy_role(policy_id=policy, role_id=role)


def test_exist_role_policy(db_setup):
    """
    Check role-policy relation exist in the database
    """
    with db_setup.RolesPoliciesManager() as rpm:
        policies_ids, roles_ids = test_add_role_policy(db_setup)
        for policy in policies_ids:
            for role in roles_ids:
                assert rpm.exist_role_policy(policy_id=policy, role_id=role)

    assert rpm.exist_role_policy(policy_id=policy, role_id=9999) == db_setup.SecurityError.ROLE_NOT_EXIST
    assert rpm.exist_role_policy(policy_id=9999, role_id=roles_ids[0]) == db_setup.SecurityError.POLICY_NOT_EXIST


def test_get_all_roles_from_user(db_setup):
    """Check all roles in one user in the database"""
    with db_setup.UserRolesManager() as urm:
        username_list, roles_ids = test_add_user_roles(db_setup)
        for user in username_list:
            roles = urm.get_all_roles_from_user(username=user)
            for role in roles:
                assert role.id in roles_ids


def test_get_all_users_from_role(db_setup):
    """Check all roles in one user in the database"""
    with db_setup.UserRolesManager() as urm:
        username_list, roles_ids = test_add_user_roles(db_setup)
        for role in roles_ids:
            users = urm.get_all_users_from_role(role_id=role)
            for user in users:
                assert user['username'] in username_list


def test_get_all_policy_from_role(db_setup):
    """Check all policies in one role in the database"""
    with db_setup.RolesPoliciesManager() as rpm:
        policies_ids, roles_ids = test_add_role_policy(db_setup)
        for role in roles_ids:
            policies = rpm.get_all_policies_from_role(role_id=role)
            for index, policy in enumerate(policies):
                assert policy.id == policies_ids[index]


def test_get_all_role_from_policy(db_setup):
    """Check all policies in one role in the database"""
    with db_setup.RolesPoliciesManager() as rpm:
        policies_ids, roles_ids = test_add_role_policy(db_setup)
        for policy in policies_ids:
            roles = [role.id for role in rpm.get_all_roles_from_policy(policy_id=policy)]
            for role_id in roles_ids:
                assert role_id in roles


def test_remove_all_roles_from_user(db_setup):
    """Remove all roles in one user in the database"""
    with db_setup.UserRolesManager() as urm:
        username_list, roles_ids = test_add_user_roles(db_setup)
        for user in username_list:
            urm.remove_all_roles_in_user(username=user)
            for index, role in enumerate(roles_ids):
                assert not urm.exist_user_role(role_id=role, username=user)


def test_remove_all_users_from_role(db_setup):
    """Remove all roles in one user in the database"""
    with db_setup.UserRolesManager() as urm:
        username_list, roles_ids = test_add_user_roles(db_setup)
        for role in roles_ids:
            urm.remove_all_users_in_role(role_id=role)
            for index, user in enumerate(username_list):
                assert not urm.exist_user_role(role_id=role, username=user)


def test_remove_all_policies_from_role(db_setup):
    """Remove all policies in one role in the database"""
    with db_setup.RolesPoliciesManager() as rpm:
        policies_ids, roles_ids = test_add_role_policy(db_setup)
        for role in roles_ids:
            rpm.remove_all_policies_in_role(role_id=role)
        for index, role in enumerate(roles_ids):
            assert not rpm.exist_role_policy(role_id=role, policy_id=policies_ids[index])


def test_remove_all_roles_from_policy(db_setup):
    """Remove all policies in one role in the database"""
    with db_setup.RolesPoliciesManager() as rpm:
        policies_ids, roles_ids = test_add_role_policy(db_setup)
        for policy in policies_ids:
            rpm.remove_all_roles_in_policy(policy_id=policy)
        for index, policy in enumerate(policies_ids):
            assert not rpm.exist_role_policy(role_id=roles_ids[index], policy_id=policy)


def test_remove_role_from_user(db_setup):
    """Remove specified role in user in the database"""
    with db_setup.UserRolesManager() as urm:
        username_list, roles_ids = test_add_user_roles(db_setup)
        for role in roles_ids:
            urm.remove_role_in_user(role_id=role, username=username_list[0])
            assert not urm.exist_user_role(role_id=role, username=username_list[0])


def test_remove_policy_from_role(db_setup):
    """Remove specified policy in role in the database"""
    with db_setup.RolesPoliciesManager() as rpm:
        policies_ids, roles_ids = test_add_role_policy(db_setup)
        for policy in policies_ids:
            rpm.remove_policy_in_role(role_id=roles_ids[0], policy_id=policy)
        for policy in policies_ids:
            assert not rpm.exist_role_policy(role_id=roles_ids[0], policy_id=policy)


def test_remove_role_from_policy(db_setup):
    """Remove specified role in policy in the database"""
    with db_setup.RolesPoliciesManager() as rpm:
        policies_ids, roles_ids = test_add_role_policy(db_setup)
        for policy in policies_ids:
            rpm.remove_policy_in_role(role_id=roles_ids[0], policy_id=policy)
        for policy in policies_ids:
            assert not rpm.exist_role_policy(role_id=roles_ids[0], policy_id=policy)


def test_update_role_from_user(db_setup):
    """Replace specified role in user in the database"""
    with db_setup.UserRolesManager() as urm:
        username_list, roles_ids = test_add_user_roles(db_setup)
        for role in roles_ids:
            urm.replace_user_role(username=username_list[0], actual_role_id=role, new_role_id=roles_ids[-1])

        assert not urm.exist_user_role(username=username_list[0], role_id=roles_ids[0])
        assert urm.exist_user_role(username=username_list[0], role_id=roles_ids[-1])


def test_update_policy_from_role(db_setup):
    """Replace specified policy in role in the database"""
    with db_setup.RolesPoliciesManager() as rpm:
        policies_ids, roles_ids = test_add_role_policy(db_setup)
        for policy in policies_ids:
            rpm.replace_role_policy(role_id=roles_ids[0], actual_policy_id=policy, new_policy_id=policies_ids[-1])

        assert not rpm.exist_role_policy(role_id=roles_ids[0], policy_id=policies_ids[0])
        assert rpm.exist_role_policy(role_id=roles_ids[0], policy_id=policies_ids[-1])
