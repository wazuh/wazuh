# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.RBAC import RBAC


def get_role(role_name):
    """
    Here we will be able to obtain a certain role, as well as to
    know that it exists or to obtain all the roles of the system.

    :param role_name: Return the information of a role
    :return: Message.
    """

    role = None
    with RBAC.RolesManager as rm:
        role = rm.get_role(name=role_name)

    return role


def get_roles():
    """
    Here we will be able to obtain all roles

    :return: Message.
    """

    roles = None
    with RBAC.RolesManager as rm:
        roles = rm.get_roles()

    return roles
