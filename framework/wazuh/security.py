# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json

from wazuh import common
from wazuh.core import security
from wazuh.rbac import orm
from wazuh.exception import WazuhError
from wazuh.utils import process_array


def get_role(role_id):
    """Returns the information of a certain role

    :param role_id: ID of the role on which the information will be collected
    :return Role information.
    """
    return_role = security.get_role_from_database(role_id)
    if return_role is None:
        raise WazuhError(4002)

    return return_role


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
    data = security.get_roles_from_database()

    return process_array(data, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)


def remove_role(role_id):
    """Removes a certain role from the system

    :param role_id: ID of the role to be removed
    :return Result of operation.
    """
    return security.remove_role_from_database(role_id)


def remove_roles(list_roles=None):
    """Removes a list of roles from the system

    :param list_roles: List of roles to be removed
    :return Result of operation.
    """
    if list_roles is None:
        list_roles = list()

    return security.remove_roles_from_database(list_roles)


def add_role(name=None, rule=None):
    """Creates a role in the system

    :param name: The new role name
    :param rule: The new rule
    :return Role information.
    """
    status = security.add_role_to_database(name, rule)
    if not status[0]:
        raise WazuhError(4005)
    elif status[0] == -1:
        raise WazuhError(4003)

    return security.get_role_from_database(role_id=status[1])


def update_role(role_id, name=None, rule=None):
    """Updates a role in the system

    :param role_id: Role id to be update
    :param name: The new role name
    :param rule: The new rule
    :return Role information.
    """
    if name is None and rule is None:
        raise WazuhError(4001)

    status = security.update_role_to_database(role_id, name, rule)
    if not status:
        raise WazuhError(4002)
    if status == -1:
        raise WazuhError(4003)

    return security.get_role_from_database(role_id=role_id)


def get_policy(policy_id):
    """Returns the information of a certain policy

    :param policy_id: ID of the policy on which the information will be collected
    :return Policy information.
    """
    return_policy = security.get_policy_from_database(policy_id)
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
    data = security.get_policies_from_database()

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
        if pm.delete_policy(policy_id):
            response['removed_policies'] = [int(policy_id)]
        else:
            response['incorrect_policies'] = [int(policy_id)]

    return response


def remove_policies(list_policies=None):
    """Removes a list of policies from the system

    :param list_policies: List of policies to be removed
    :return Result of operation.
    """
    if list_policies is None:
        list_policies = list()

    return security.remove_policies_from_database(list_policies)


def add_policy(name=None, policy=None):
    """Creates a policy in the system

    :param name: The new policy name
    :param policy: The new policy
    :return Policy information.
    """
    status = security.add_policy_to_database(name, policy)
    if not status[0]:
        raise WazuhError(4009)
    elif status[0] == -1:
        raise WazuhError(4006)
    elif status[0] == -2:
        raise WazuhError(4012)

    return get_policy(policy_id=status[1])


def update_policy(policy_id, name=None, policy=None):
    """Updates a policy in the system

    :param policy_id: Policy id to be update
    :param name: The new policy name
    :param policy: The new policy
    :return Policy information.
    """
    if name is None and policy is None:
        raise WazuhError(4001)

    status = security.update_policy_to_database(policy_id, name, policy)
    if not status:
        raise WazuhError(4007)
    elif status == -1:
        raise WazuhError(4006)
    elif status == -2:
        raise WazuhError(4013)

    return get_policy(policy_id=policy_id)


def set_role_policy(role_id, policies_ids):
    """Create a relationship between a role and a policy

    :param role_id: The new role_id
    :param policies_ids: List of policies ids
    :return Role-Policies information.
    """
    with orm.PoliciesManager() as pm:
        for policy_id in policies_ids:
            if not pm.get_policy_by_id(policy_id):
                raise WazuhError(4007, extra_message=str(policy_id))

    with orm.RolesPoliciesManager() as rpm:
        for policy_id in policies_ids:
            role_policy = rpm.exist_role_policy(role_id, policy_id)
            if role_policy:
                raise WazuhError(4011,
                                 extra_message='Role id ' + str(role_id) + ' - ' + 'Policy id ' + str(policy_id))
            elif role_policy == -1:
                raise WazuhError(4002, extra_message='Role id ' + str(role_id))

    with orm.RolesPoliciesManager() as rpm:
        for policy_id in policies_ids:
            status = rpm.add_policy_to_role(role_id=role_id, policy_id=policy_id)
            if not status:
                raise WazuhError(4008)
            if status == -1:
                raise WazuhError(4002)
            if status == -2:
                raise WazuhError(4007)

    return security.get_role_from_database(role_id=role_id)


def remove_role_policy(role_id, policies_ids):
    """Removes a relationship between a role and a policy

    :param role_id: The new role_id
    :param policies_ids: List of policies ids
    :return Result of operation.
    """
    with orm.PoliciesManager() as pm:
        for policy_id in policies_ids:
            if not pm.get_policy_by_id(policy_id):
                raise WazuhError(4007, extra_message=str(policy_id))

    with orm.RolesPoliciesManager() as rpm:
        for policy_id in policies_ids:
            role_policy = rpm.exist_role_policy(role_id, policy_id)
            if not role_policy:
                raise WazuhError(4010,
                                 extra_message='Role id ' + str(role_id) + ' - ' + 'Policy id ' + str(policy_id))
            elif role_policy == -1:
                raise WazuhError(4002, extra_message='Role id ' + str(role_id))

    with orm.RolesPoliciesManager() as rpm:
        for policy_id in policies_ids:
            status = rpm.remove_policy_in_role(role_id=role_id, policy_id=policy_id)
            if not status:
                raise WazuhError(4008)

    return security.get_role_from_database(role_id=role_id)
