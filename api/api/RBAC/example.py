# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import api.RBAC.RBAC as rbac
from api.constants import SECURITY_PATH

db_path = os.path.join(SECURITY_PATH, 'RBAC.db')

list_roles_id = list()
with rbac.RolesManager() as rm:
    rm.add_role(name='NewRole', role='NewRoleDefinition')
    print(rm.get_role(name='NewRole').name)
    list_roles_id.append(rm.get_role(name="NewRole").id)
    rm.add_role(name='NewRole1', role='NewRoleDefinition')
    print(rm.get_role(name='NewRole1').name)
    list_roles_id.append(rm.get_role(name="NewRole1").id)

list_policy_id = list()
with rbac.PoliciesManager() as pm:
    pm.add_policy(name='NewPolicy', policy='NewPolicyDefinition')
    print(pm.get_policy(name='NewPolicy').name)
    list_policy_id.append(pm.get_policy(name="NewPolicy").id)
    pm.add_policy(name='NewPolicy1', policy='NewPolicyDefinition')
    print(pm.get_policy(name='NewPolicy1').name)
    list_policy_id.append(pm.get_policy(name="NewPolicy1").id)

with rbac.RolesPoliciesManager() as rpm:
    for p_id in list_policy_id:
        rpm.add_policy_to_role(role_id=rm.get_role(name='NewRole').id, policy_id=p_id)

    rpm.get_all_policies_from_role(role_id=rm.get_role(name='NewRole').id)
    print('Tests exist: {}'.format(rpm.exist_role_policy(role_id=rm.get_role(name='NewRole').id, policy_id=list_policy_id[1])))
    print('Test invalid replace: {}'.format(rpm.replace_role_policy(role_id=rm.get_role(name='NewRole').id,
                                                                   actual_policy_id=list_policy_id[0],
                                                                   new_policy_id=list_policy_id[-1] + 1)))
    pm.add_policy(name='NewPolicy2', policy='NewPolicyDefinition')
    list_policy_id.append(pm.get_policy(name="NewPolicy2").id)

    print('Test valid replace: {}'.format(rpm.replace_role_policy(role_id=rm.get_role(name='NewRole').id,
                                                                     actual_policy_id=list_policy_id[0],
                                                                     new_policy_id=list_policy_id[-1])))
    print('Last policy added: {}'.format(pm.get_policy(name='NewPolicy2').name))
    # With this we can check on cascade remove
    pm.delete_policy_by_name(pm.get_policy(name='NewPolicy2').name)
    if pm.get_policy(name='NewPolicy2') is None:
        print('Last policy added: NewPolicy2 deleted')

    if rpm.remove_all_policies_in_role(rm.get_role(name='NewRole').id):
        print('All policies deleted for {} role'.format(rm.get_role(name='NewRole').name))
    else:
        print('Problem removing policies for {} role'.format(rm.get_role(name='NewRole').name))

    pm.delete_policy_by_name(pm.get_policy(name='NewPolicy2').name)
    if pm.get_policy(name='NewPolicy2') is None:
        print('Last policy added: NewPolicy2 deleted')

    # rpm.add_role_to_policy(policy_id=1, role_id=2)

    #
    # for r_id in list_roles_id:
    #     rpm.add_role_to_policy(policy_id=pm.get_role(name='NewRole').id, policy_id=p_id)
