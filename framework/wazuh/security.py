# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json

from wazuh import common
from wazuh.exception import WazuhError
from wazuh.rbac import orm
from wazuh.rbac.decorators import expose_resources
from wazuh.rbac.orm import SecurityError
from wazuh.utils import process_array


@expose_resources(actions=['role:read'], resources=['role:id:{role_id}'], target_param='role_id')
def get_role(role_id):
    """Returns the information of a certain role

    :param role_id: ID of the role on which the information will be collected
    :return Role information.
    """
    return_role = None
    with orm.RolesManager() as rm:
        for r_id in role_id:
            role = rm.get_role_id(r_id)
            if role and role != SecurityError.ROLE_NOT_EXIST:
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


@expose_resources(actions=['role:read'], resources=['role:id:*'], target_param='role_id')
def get_roles(offset=0, limit=common.database_limit, sort_by=None,
              sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
    """Returns information from all system roles, does not return information from its associated policies

    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    data = list()

    with orm.RolesManager() as rm:
        roles = rm.get_roles()
        for role in roles:
            dict_role = role.to_dict()
            dict_role.pop('policies', None)
            dict_role['rule'] = json.loads(dict_role['rule'])
            data.append(dict_role)

    return process_array(data, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)


def remove_role(role_id):
    """Removes a certain role from the system

    :param role_id: ID of the role to be removed
    :return Result of operation.
    """
    response = dict()

    with orm.RolesManager() as rm:
        if rm.delete_role(role_id):
            response['removed_roles'] = [int(role_id)]
        else:
            response['incorrect_roles'] = [int(role_id)]

    return response


def remove_roles(list_roles=None):
    """Removes a list of roles from the system

    :param list_roles: List of roles to be removed
    :return Result of operation.
    """
    if list_roles is None:
        list_roles = list()
    status_correct = list()
    response = dict()

    with orm.RolesManager() as rm:
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


def add_role(name=None, rule=None):
    """Creates a role in the system

    :param name: The new role name
    :param rule: The new rule
    :return Role information.
    """
    with orm.RolesManager() as rm:
        status = rm.add_role(name=name, rule=rule)
        if status == SecurityError.ALREADY_EXIST:
            raise WazuhError(4005)
        if status == SecurityError.INVALID:
            raise WazuhError(4003)

    return rm.get_role(name=name).to_dict()


def update_role(role_id, name=None, rule=None):
    """Updates a role in the system

    :param role_id: Role id to be update
    :param name: The new role name
    :param rule: The new rule
    :return Role information.
    """
    if name is None and rule is None:
        raise WazuhError(4001)

    with orm.RolesManager() as rm:
        status = rm.update_role(role_id=role_id, name=name, rule=rule)
        if status == SecurityError.ALREADY_EXIST:
            raise WazuhError(4005)
        if status == SecurityError.INVALID:
            raise WazuhError(4003)
        if status == SecurityError.ROLE_NOT_EXIST:
            raise WazuhError(4002)

    return rm.get_role_id(role_id=role_id).to_dict()


def get_policy(policy_id):
    """Returns the information of a certain policy

    :param policy_id: ID of the policy on which the information will be collected
    :return Policy information.
    """
    return_policy = None
    with orm.PoliciesManager() as pm:
        policy = pm.get_policy_by_id(policy_id)
        if policy and policy != SecurityError.POLICY_NOT_EXIST:
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

    return return_policy


def get_policies(offset=0, limit=common.database_limit, sort_by=None,
                 sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
    """Here we will be able to obtain all policies

    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    data = list()
    with orm.PoliciesManager() as pm:
        policies = pm.get_policies()
        for policy in policies:
            dict_policy = policy.to_dict()
            dict_policy.pop('roles', None)
            dict_policy['policy'] = json.loads(dict_policy['policy'])
            data.append(dict_policy)

    return process_array(data, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)


def remove_policy(policy_id):
    """Removes a certain policy from the system

    :param policy_id: ID of the policy to be removed
    :return Result of operation.
    """
    response = dict()
    with orm.PoliciesManager() as pm:
        response['removed_policies'] = [int(policy_id)] if pm.delete_policy(policy_id) else [int(policy_id)]

    return response


def remove_policies(list_policies=None):
    """Removes a list of policies from the system

    :param list_policies: List of policies to be removed
    :return Result of operation.
    """
    if list_policies is None:
        list_policies = list()
    status_correct = list()
    response = dict()

    with orm.PoliciesManager() as pm:
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


def add_policy(name=None, policy=None):
    """Creates a policy in the system

    :param name: The new policy name
    :param policy: The new policy
    :return Policy information.
    """
    with orm.PoliciesManager() as pm:
        status = pm.add_policy(name=name, policy=policy)
        if status == SecurityError.ALREADY_EXIST:
            raise WazuhError(4009)
        if status == SecurityError.INVALID:
            raise WazuhError(4006)

    return pm.get_policy(name).to_dict()


def update_policy(policy_id, name=None, policy=None):
    """Updates a policy in the system

    :param policy_id: Policy id to be update
    :param name: The new policy name
    :param policy: The new policy
    :return Policy information.
    """
    if name is None and policy is None:
        raise WazuhError(4001)

    with orm.PoliciesManager() as pm:
        status = pm.update_policy(policy_id=policy_id, name=name, policy=policy)
        if status == SecurityError.ALREADY_EXIST:
            raise WazuhError(4013)
        if status == SecurityError.INVALID:
            raise WazuhError(4006)
        if status == SecurityError.POLICY_NOT_EXIST:
            raise WazuhError(4007)

    return pm.get_policy_by_id(policy_id).to_dict()


def set_role_policy(role_id, policies_ids):
    """Create a relationship between a role and a policy

    :param role_id: The new role_id
    :param policies_ids: List of policies ids
    :return Role-Policies information.
    """
    with orm.RolesPoliciesManager() as rpm:
        for policy_id in policies_ids:
            role_policy = rpm.exist_role_policy(role_id, policy_id)
            if role_policy is True:
                raise WazuhError(4011,
                                 extra_message='Role id ' + str(role_id) + ' - ' + 'Policy id ' + str(policy_id))
            elif role_policy == SecurityError.ROLE_NOT_EXIST:
                raise WazuhError(4002, extra_message='Role id ' + str(role_id))
            elif role_policy == SecurityError.POLICY_NOT_EXIST:
                raise WazuhError(4007, extra_message='Policy id ' + str(policy_id))

    with orm.RolesPoliciesManager() as rpm:
        for policy_id in policies_ids:
            status = rpm.add_policy_to_role(role_id=role_id, policy_id=policy_id)
            if status == SecurityError.ADMIN_RESOURCES:
                raise WazuhError(4008)

    return get_role(role_id=role_id)


def remove_role_policy(role_id, policies_ids):
    """Removes a relationship between a role and a policy

    :param role_id: The new role_id
    :param policies_ids: List of policies ids
    :return Result of operation.
    """
    with orm.RolesPoliciesManager() as rpm:
        for policy_id in policies_ids:
            role_policy = rpm.exist_role_policy(role_id, policy_id)
            if not role_policy:
                raise WazuhError(4010,
                                 extra_message='Role id ' + str(role_id) + ' - ' + 'Policy id ' + str(policy_id))
            elif role_policy == SecurityError.ROLE_NOT_EXIST:
                raise WazuhError(4002, extra_message='Role id ' + str(role_id))
            elif role_policy == SecurityError.POLICY_NOT_EXIST:
                raise WazuhError(4007, extra_message='Policy id ' + str(policy_id))

    with orm.RolesPoliciesManager() as rpm:
        for policy_id in policies_ids:
            status = rpm.remove_policy_in_role(role_id=role_id, policy_id=policy_id)
            if status == SecurityError.ADMIN_RESOURCES:
                raise WazuhError(4008)

    return get_role(role_id=role_id)
