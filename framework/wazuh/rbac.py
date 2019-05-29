# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.RBAC import RBAC
from wazuh.exception import WazuhException, WazuhInternalError, WazuhError
from wazuh import common
from wazuh.utils import cut_array, sort_array, search_array, load_wazuh_xml


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

    def __init__(self, id, name, rule, policy=None):
        self.id = id
        self.name = name
        self.rule = rule
        self.policies = policy

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
    def get_role(role_id):
        """
        Here we will be able to obtain a certain role, as well as to
        know that it exists or to obtain all the roles of the system.


        :param role_id: Return the information of a role
        :return: Message.
        """

        return_roles = list()

        with RBAC.RolesManager() as rm:
            role = rm.get_role_id(id=role_id)
            if role is not None:
                return_roles.append(role.to_dict())

        return {'items': return_roles, 'totalItems': len(return_roles)}


    @staticmethod
    def get_roles(offset=0, limit=common.database_limit):
        """
        Here we will be able to obtain all roles

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :return: Message.
        """

        return_roles = list()

        with RBAC.RolesManager() as rm:
            roles = rm.get_roles()
            for role in roles:
                return_roles.append(role.to_dict())

        return {'items': cut_array(return_roles, offset, limit), 'totalItems': len(return_roles)}

    @staticmethod
    def remove_role(role_id):
        """
        Here we will be able to delete a role

        :param role_id: Role to be deleted
        :return: Message.
        """

        response = dict()

        with RBAC.RolesManager() as rm:
            if rm.delete_role(role_id):
                response['affected_roles'] = list(role_id)
            else:
                response['incorrect_roles'] = list(role_id)

        return response


    @staticmethod
    def remove_roles(list_roles):
        """
        Here we will be able to delete all roles

        :param list_roles: List of roles to be deleted
        :return: Message.
        """

        status_correct = list()
        response = dict()

        with RBAC.RolesManager() as rm:
            if len(list_roles) > 0:
                for role in list_roles:
                    if rm.delete_role(role):
                        status_correct.append(role)
                response['affected_roles'] = status_correct
                response['incorrect_roles'] = list(set(list_roles) ^ set(status_correct))
            else:
                rm.delete_all_roles()
                response['affected_roles'] = list()
                response['affected_roles'].append('All possible roles have been deleted')

        return response

    @staticmethod
    def update_role(role_id):
        """
        Here we will be able to update a specified role

        :param role_id: Role id to be delete
        :return: Message.
        """

        status_correct = list()
        response = dict()

        with RBAC.RolesManager() as rm:
            if len(list_roles) > 0:
                for role in list_roles:
                    if rm.delete_role(role):
                        status_correct.append(role)
                response['affected_roles'] = status_correct
                response['incorrect_roles'] = list(set(list_roles) ^ set(status_correct))
            else:
                rm.delete_all_roles()
                response['affected_roles'] = list()
                response['affected_roles'].append('All possible roles have been deleted')

        return response
