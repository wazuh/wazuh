# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json

from wazuh import common
from wazuh.rbac import rbac
from wazuh.exception import WazuhError
from wazuh.utils import cut_array, sort_array, search_array


class Role:
    """Role Object.
    """
    SORT_FIELDS = ['name']

    def __init__(self, role_id=None, name=None, rule=None, policies=None):
        self.role_id = role_id
        self.name = name
        self.rule = rule
        if policies is None:
            self.policies = list()
        else:
            self.policies = policies

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        return {'id': self.role_id, 'name': self.name, 'rule': self.rule, 'policies': self.policies}

    @staticmethod
    def get_role(role_id):
        """Returns the information of a certain role

        :param role_id: ID of the role on which the information will be collected
        :return Role information.
        """
        return_role = None
        with rbac.RolesManager() as rm:
            role = rm.get_role_id(role_id)
            if role is not None:
                return_role = role.to_dict()
                return_role['rule'] = json.loads(return_role['rule'])
                # It is necessary to load the policies (json.loads) for a correct visualization
                for index, policy in enumerate(return_role['policies']):
                    return_role['policies'][index]['policy'] = \
                        json.loads(return_role['policies'][index]['policy'])
                # Removes the policies field because when creating a role it is not connected to any of them.
                if len(return_role['policies']) == 0:
                    return_role.pop('policies', None)

        if return_role is None:
            raise WazuhError(4002)

        return return_role

    @staticmethod
    def get_roles(offset=0, limit=common.database_limit, search=None, sort=None):
        """Returns information from all system roles, does not return information from its associated policies

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return Roles information.
        """
        return_roles = list()

        with rbac.RolesManager() as rm:
            roles = rm.get_roles()
            for role in roles:
                dict_role = role.to_dict()
                dict_role.pop('policies', None)
                dict_role['rule'] = json.loads(dict_role['rule'])
                return_roles.append(dict_role)

        if search:
            return_roles = search_array(return_roles, search['value'], search['negation'])

        if sort:
            return_roles = sort_array(return_roles, sort['fields'], sort['order'])
        else:
            return_roles = sort_array(return_roles, ['id'], 'asc')

        return {'items': cut_array(return_roles, offset, limit), 'totalItems': len(return_roles)}

    @staticmethod
    def remove_role(role_id):
        """Removes a certain role from the system

        :param role_id: ID of the role to be removed
        :return Result of operation.
        """
        response = dict()

        with rbac.RolesManager() as rm:
            if rm.delete_role(role_id):
                response['removed_roles'] = [int(role_id)]
            else:
                response['incorrect_roles'] = [int(role_id)]

        return response

    @staticmethod
    def remove_roles(list_roles=None):
        """Removes a list of roles from the system

        :param list_roles: List of roles to be removed
        :return Result of operation.
        """
        if list_roles is None:
            list_roles = list()
        status_correct = list()
        response = dict()

        with rbac.RolesManager() as rm:
            if len(list_roles) > 0:
                for role in list_roles:
                    if rm.delete_role(role):
                        status_correct.append(int(role))
                response['removed_roles'] = status_correct
                # Symmetric difference: The symmetric difference of two sets A and B is
                # the set of elements which are in either of the sets A or B but not in both.
                response['incorrect_roles'] = list(set(list_roles) ^ set(status_correct))
            else:
                response['removed_roles'] = rm.delete_all_roles()

        return response

    @staticmethod
    def add_role(name=None, rule=None):
        """Creates a role in the system

        :param name: The new role name
        :param rule: The new rule
        :return Role information.
        """
        with rbac.RolesManager() as rm:
            status = rm.add_role(name=name, rule=rule)
            if not status:
                raise WazuhError(4005)
            if status == -1:
                raise WazuhError(4003)

        return Role.get_role(role_id=rm.get_role(name=name).id)

    @staticmethod
    def update_role(role_id, name=None, rule=None):
        """Updates a role in the system

        :param role_id: Role id to be update
        :param name: The new role name
        :param rule: The new rule
        :return Role information.
        """
        if name is None and rule is None:
            raise WazuhError(4001)

        with rbac.RolesManager() as rm:
            status = rm.update_role(role_id=role_id, name=name, rule=rule)
            if not status:
                raise WazuhError(4002)
            if status == -1:
                raise WazuhError(4003)

        return Role.get_role(role_id=role_id)


class Policy:
    """Policy Object.
    """
    SORT_FIELDS = ['name']

    def __init__(self, policy_id=None, name=None, policy=None, roles=None):
        self.policy_id = policy_id
        self.name = name
        self.policy = policy
        if roles is None:
            self.roles = list()
        else:
            self.roles = roles

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        return {'id': self.policy_id, 'name': self.name, 'policy': self.policy, 'roles': self.roles}

    @staticmethod
    def get_policy(policy_id):
        """Returns the information of a certain policy

        :param policy_id: ID of the policy on which the information will be collected
        :return Policy information.
        """
        return_policy = None
        with rbac.PoliciesManager() as pm:
            policy = pm.get_policy_by_id(policy_id)
            if policy is not None:
                return_policy = policy.to_dict()
                return_policy['policy'] = json.loads(return_policy['policy'])
                # It is necessary to load the roles (json.loads) for a correct visualization
                for index, role in enumerate(return_policy['roles']):
                    return_policy['roles'][index]['rule'] = \
                        json.loads(return_policy['roles'][index]['rule'])
                # Removes the roles field because when creating a policy it is not connected to any of them.
                if len(return_policy['roles']) == 0:
                    return_policy.pop('roles', None)

        if return_policy is None:
            raise WazuhError(4007)

        # return {'items': return_policies, 'totalItems': len(return_policies)}
        return return_policy

    @staticmethod
    def get_policies(offset=0, limit=common.database_limit, search=None, sort=None):
        """Here we will be able to obtain all policies

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param search: Looks for items with the specified string.
        :return Policies information.
        """
        return_policies = list()
        with rbac.PoliciesManager() as pm:
            policies = pm.get_policies()
            for policy in policies:
                dict_policy = policy.to_dict()
                dict_policy.pop('roles', None)
                dict_policy['policy'] = json.loads(dict_policy['policy'])
                return_policies.append(dict_policy)

        if search:
            return_policies = search_array(return_policies, search['value'], search['negation'])

        if sort:
            return_policies = sort_array(return_policies, sort['fields'], sort['order'])
        else:
            return_policies = sort_array(return_policies, ['id'], 'asc')

        return {'items': cut_array(return_policies, offset, limit), 'totalItems': len(return_policies)}

    @staticmethod
    def remove_policy(policy_id):
        """Removes a certain policy from the system

        :param policy_id: ID of the policy to be removed
        :return Result of operation.
        """
        response = dict()
        with rbac.PoliciesManager() as pm:
            if pm.delete_policy(policy_id):
                response['removed_policies'] = [int(policy_id)]
            else:
                response['incorrect_policies'] = [int(policy_id)]

        return response

    @staticmethod
    def remove_policies(list_policies=None):
        """Removes a list of policies from the system

        :param list_policies: List of policies to be removed
        :return Result of operation.
        """
        if list_policies is None:
            list_policies = list()
        status_correct = list()
        response = dict()

        with rbac.PoliciesManager() as pm:
            if len(list_policies) > 0:
                for policy in list_policies:
                    if pm.delete_policy(policy):
                        status_correct.append(int(policy))
                response['removed_policies'] = status_correct
                # Symmetric difference: The symmetric difference of two sets A and B is
                # the set of elements which are in either of the sets A or B but not in both.
                response['incorrect_policies'] = list(set(list_policies) ^ set(status_correct))
            else:
                response['removed_policies'] = pm.delete_all_policies()

        return response

    @staticmethod
    def add_policy(name=None, policy=None):
        """Creates a policy in the system

        :param name: The new policy name
        :param policy: The new policy
        :return Policy information.
        """
        with rbac.PoliciesManager() as pm:
            status = pm.add_policy(name=name, policy=policy)
            if not status:
                raise WazuhError(4009)
            if status == -1:
                raise WazuhError(4006)
            if status == -2:
                raise WazuhError(4012)

        return Policy.get_policy(policy_id=pm.get_policy(name=name).id)

    @staticmethod
    def update_policy(policy_id, name=None, policy=None):
        """Updates a policy in the system

        :param policy_id: Policy id to be update
        :param name: The new policy name
        :param policy: The new policy
        :return Policy information.
        """
        if name is None and policy is None:
            raise WazuhError(4001)

        with rbac.PoliciesManager() as pm:
            status = pm.update_policy(policy_id=policy_id, name=name, policy=policy)
            if not status:
                raise WazuhError(4007)
            if status == -1:
                raise WazuhError(4006)
            if status == -2:
                raise WazuhError(4013)

        return Policy.get_policy(policy_id=policy_id)


class RolePolicy:
    """RolePolicy Object.
    """
    SORT_FIELDS = ['name']

    def __init__(self, role_id=None, policy_id=None):
        self.role_id = role_id
        self.policy_id = policy_id

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        return {'role_id': self.role_id, 'policy_id': self.policy_id}

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
    def set_role_policy(role_id, policies_ids):
        """Create a relationship between a role and a policy

        :param role_id: The new role_id
        :param policies_ids: List of policies ids
        :return Role-Policies information.
        """
        with rbac.PoliciesManager() as pm:
            for policy_id in policies_ids:
                if not pm.get_policy_by_id(policy_id):
                    raise WazuhError(4007, extra_message=str(policy_id))

        with rbac.RolesPoliciesManager() as rpm:
            for policy_id in policies_ids:
                role_policy = rpm.exist_role_policy(role_id, policy_id)
                if role_policy:
                    raise WazuhError(4011,
                                     extra_message='Role id ' + str(role_id) + ' - ' + 'Policy id ' + str(policy_id))
                elif role_policy == -1:
                    raise WazuhError(4002, extra_message='Role id ' + str(role_id))

        with rbac.RolesPoliciesManager() as rpm:
            for policy_id in policies_ids:
                status = rpm.add_policy_to_role(role_id=role_id, policy_id=policy_id)
                if not status:
                    raise WazuhError(4008)
                if status == -1:
                    raise WazuhError(4002)
                if status == -2:
                    raise WazuhError(4007)

        return Role.get_role(role_id=role_id)

    @staticmethod
    def remove_role_policy(role_id, policies_ids):
        """Removes a relationship between a role and a policy

        :param role_id: The new role_id
        :param policies_ids: List of policies ids
        :return Result of operation.
        """
        with rbac.PoliciesManager() as pm:
            for policy_id in policies_ids:
                if not pm.get_policy_by_id(policy_id):
                    raise WazuhError(4007, extra_message=str(policy_id))

        with rbac.RolesPoliciesManager() as rpm:
            for policy_id in policies_ids:
                role_policy = rpm.exist_role_policy(role_id, policy_id)
                if not role_policy:
                    raise WazuhError(4010,
                                     extra_message='Role id ' + str(role_id) + ' - ' + 'Policy id ' + str(policy_id))
                elif role_policy == -1:
                    raise WazuhError(4002, extra_message='Role id ' + str(role_id))

        with rbac.RolesPoliciesManager() as rpm:
            for policy_id in policies_ids:
                status = rpm.remove_policy_in_role(role_id=role_id, policy_id=policy_id)
                if not status:
                    raise WazuhError(4008)

        return Role.get_role(role_id=role_id)
