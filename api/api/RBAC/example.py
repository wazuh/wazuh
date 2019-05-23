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
    rm.update_role(id=rm.get_role(name='NewRole').id, name='ReNewName', role='ReNewRole')
    print(rm.get_role(name='ReNewName').name)
    # rm.delete_role(rm.get_role(name='ReNewName').id)
    rm.add_policy_to_role(role_id=rm.get_role(name='ReNewName').id, policy_id=rm.get_role(name='ReNewName').id)
