# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
from unittest.mock import patch

import pytest

test_path = os.path.dirname(os.path.realpath(__file__))
test_data_path = os.path.join(test_path, 'data')


@pytest.fixture(scope='module')
def import_RBAC():
    with patch('api.constants.SECURITY_PATH', new=test_data_path):
        import api.RBAC.RBAC as rbac
        db_path = os.path.join(test_data_path, 'RBAC.db')
        assert (os.path.exists(db_path))
        yield rbac
        os.unlink(db_path)


def test_database_init(import_RBAC):
    """
    Checks users db is properly initialized
    """
    with import_RBAC.RolesManager() as rm:
        assert(rm.get_role('wazuh'))
        assert(rm.get_role('wazuh-app'))


def test_add_role(import_RBAC):
    """
    Checks role is added to database
    """
    with import_RBAC.RolesManager() as rm:
        # New role
        rm.add_role('newRole', 'UnittestRole')
        assert(rm.get_role('newRole'))
        # New role
        rm.add_role('newRole1', 'UnittestRole1')
        assert (rm.get_role('newRole1'))

        # Obtain not existent role
        assert(not rm.get_role('noexist'))


def test_add_policy(import_RBAC):
    """
    Checks policy is added to database
    """
    with import_RBAC.PoliciesManager() as pm:
        # New policy
        pm.add_policy('newPolicy', 'UnittestPolicy')
        assert(pm.get_policy('newPolicy'))
        # New policy
        pm.add_policy('newPolicy1', 'UnittestPolicy1')
        assert (pm.get_policy('newPolicy1'))

        # Obtain not existent policy
        assert(not pm.get_policy('noexist'))


def test_get_roles(import_RBAC):
    """
    Checks roles in the database
    """
    with import_RBAC.RolesManager() as rm:
        roles = rm.get_roles()
        assert roles
        for rol in roles:
            assert (isinstance(rol.name, str))

        assert (roles[0].name == 'wazuh')


def test_get_policies(import_RBAC):
    """
    Checks policies in the database
    """
    with import_RBAC.PoliciesManager() as pm:
        policies = pm.get_policies()
        assert policies
        for policy in policies:
            assert (isinstance(policy.name, str))

        assert (policies[0].name == 'newPolicy')


def test_delete_roles(import_RBAC):
    """
    Checks delete roles in the database
    """
    with import_RBAC.RolesManager() as rm:
        rm.add_role(name='toDelete', role='UnittestRole')
        len_roles = len(rm.get_roles())
        rm.delete_role_by_name(role_name='toDelete')
        assert (len_roles == (len(rm.get_roles()) + 1))


def test_delete_all_roles(import_RBAC):
    """
    Checks delete roles in the database
    """
    with import_RBAC.RolesManager() as rm:
        assert rm.delete_all_roles()
        rm.add_role(name='toDelete', role='UnittestRole')
        rm.add_role(name='toDelete1', role='UnittestRole1')
        len_roles = len(rm.get_roles())
        rm.delete_all_roles()
        assert (len_roles == (len(rm.get_roles()) + 2))


def test_delete_policies(import_RBAC):
    """
    Checks delete policies in the database
    """
    with import_RBAC.PoliciesManager() as pm:
        pm.add_policy(name='toDelete', policy='UnittestPolicy')
        len_policies = len(pm.get_policies())
        pm.delete_policy_by_name(policy_name='toDelete')
        assert (len_policies == (len(pm.get_policies()) + 1))


def test_delete_all_policies(import_RBAC):
    """
    Checks delete policies in the database
    """
    with import_RBAC.PoliciesManager() as pm:
        assert pm.delete_all_policies()
        pm.add_policy(name='toDelete', policy='UnittestPolicy')
        pm.add_policy(name='toDelete1', policy='UnittestPolicy1')
        len_policies = len(pm.get_policies())
        pm.delete_all_policies()
        assert (len_policies == (len(pm.get_policies()) + 2))


def test_update_role(import_RBAC):
    """
    Checks update a role in the database
    """
    with import_RBAC.RolesManager() as rm:
        rm.add_role(name='toUpdate', role='UnittestRole')
        tid = rm.get_role(name='toUpdate').id
        tname = rm.get_role(name='toUpdate').name
        rm.update_role(role_id=tid, name='updatedName', role='updatedDefinition')
        assert (tid == rm.get_role(name='updatedName').id)
        assert (tname == 'toUpdate')
        assert (rm.get_role(name='updatedName').name == 'updatedName')


def test_update_policy(import_RBAC):
    """
    Checks update a policy in the database
    """
    with import_RBAC.PoliciesManager() as pm:
        pm.add_policy(name='toUpdate', policy='UnittestPolicy')
        tid = pm.get_policy(name='toUpdate').id
        tname = pm.get_policy(name='toUpdate').name
        pm.update_policy(policy_id=tid, name='updatedName', policy='updatedDefinition')
        assert (tid == pm.get_policy(name='updatedName').id)
        assert (tname == 'toUpdate')
        assert (pm.get_policy(name='updatedName').name == 'updatedName')