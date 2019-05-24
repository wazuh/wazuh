# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

import api.RBAC.RBAC as rbac
from api.constants import SECURITY_PATH

db_path = os.path.join(SECURITY_PATH, 'RBAC.db')

with rbac.RolesManager() as rm:
    rm.add_role(name='NewRole', role='NewRoleDefinition')
    print(rm.get_role(name='NewRole').name)
    rm.add_role(name='NewRole1', role='NewRoleDefinition')
    print(rm.get_role(name='NewRole1').name)

policy_id = list()
with rbac.PoliciesManager() as pm:
    pm.add_policy(name='NewPolicy', policy='NewPolicyDefinition')
    print(pm.get_policy(name='NewPolicy').name)
    policy_id.append(pm.get_policy(name="NewPolicy").id)
    pm.add_policy(name='NewPolicy1', policy='NewPolicyDefinition')
    print(pm.get_policy(name='NewPolicy1').name)
    policy_id.append(pm.get_policy(name="NewPolicy1").id)

with rbac.RolesManager() as rm:
    for p_id in policy_id:
        rm.add_policy_to_role(role_id=rm.get_role(name='NewRole').id, policy_id=p_id)

    rm.get_all_policies(role_id=rm.get_role(name='NewRole').id)
    print('Tests exist: {}'.format(rm.exist_role_policy(role_id=rm.get_role(name='NewRole').id, policy_id=policy_id[1])))
    print('Test invalid replace: {}'.format(rm.replace_role_policy(role_id=rm.get_role(name='NewRole').id,
                                                                 actual_policy_id=policy_id[0],
                                                                 new_policy_id=policy_id[-1]+1)))
    with rbac.PoliciesManager() as pm:
        pm.add_policy(name='NewPolicy2', policy='NewPolicyDefinition')
        policy_id.append(pm.get_policy(name="NewPolicy2").id)
    print('Test valid replace: {}'.format(rm.replace_role_policy(role_id=rm.get_role(name='NewRole').id,
                                                                   actual_policy_id=policy_id[0],
                                                                   new_policy_id=policy_id[-1])))

    print(rm.remove_policy_all_in_role(rm.get_role(name='NewRole').id))
