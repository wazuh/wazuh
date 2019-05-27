# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.RBAC import RBAC

def roles(role_name=None):
    """
    Here we will be able to obtain a certain role, as well as to
    know that it exists or to obtain all the roles of the system.

    :param role_name: Return the information of a role
    :return: Message.
    """

    if role_name is not None:
        with RBAC.RolesManager as rm:
            roles = rm.get_role(name=role_name)
    else:
        pass
