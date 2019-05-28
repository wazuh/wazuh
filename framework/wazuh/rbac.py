# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.RBAC import RBAC
from wazuh.exception import WazuhException, WazuhInternalError, WazuhError


class Role:
    """
    Role Object.
    """

    SORT_FIELDS = ['name']

    def __init__(self):
        self.id = None
        self.name = None
        self.rule = None
        self.policies = list()

    def __str__(self):
        return str(self.to_dict())

    def __lt__(self, other):
        if isinstance(other, Role):
            return self.id < other.id
        else:
            raise WazuhInternalError(1204)

    def __le__(self, other):
        if isinstance(other, Role):
            return self.id <= other.id
        else:
            raise WazuhInternalError(1204)

    def __gt__(self, other):
        if isinstance(other, Role):
            return self.id > other.id
        else:
            raise WazuhInternalError(1204)

    def __ge__(self, other):
        if isinstance(other, Role):
            return self.id >= other.id
        else:
            raise WazuhInternalError(1204)

    def to_dict(self):
        return {'id': self.id, 'name': self.name, 'rule': self.rule, 'policies': self.policies}

    def add_policy(self, policy):
        """
        Adds a policy to the policies list.
        :param policy: Policy to add (string or list)
        """

        Role.__add_unique_element(self.policies, policy)

    @staticmethod
    def __add_unique_element(src_list, element):
        new_list = []

        if type(element) in [list, tuple]:
            new_list.extend(element)
        else:
            new_list.append(element)

        for item in new_list:
            if item is not None and item != '':
                i = item.strip()
                if i not in src_list:
                    src_list.append(i)

    @staticmethod
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


    @staticmethod
    def get_roles():
        """
        Here we will be able to obtain all roles

        :return: Message.
        """
        print('Here')

        roles = None
        with RBAC.RolesManager as rm:
            roles = rm.get_roles()

        return roles