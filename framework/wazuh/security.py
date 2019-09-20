# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import json
import re

from api.authentication import AuthenticationManager
from wazuh import common
from wazuh.exception import WazuhError, WazuhInternalError, create_exception_dic
from wazuh.rbac import orm
from wazuh.rbac.decorators import expose_resources
from wazuh.rbac.orm import SecurityError
from wazuh.utils import process_array

# Minimum eight characters, at least one uppercase letter, one lowercase letter, one number and one special character:
_user_password = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[_@$!%*?&-])[A-Za-z\d@$!%*?&-_]{8,}$')


def get_users(offset=0, limit=common.database_limit, sort_by=None,
              sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
    """Get the information of all users

    :return: Information about users
    """
    with AuthenticationManager() as auth:
        result = auth.get_users()

    if not result or len(result) == 0:
        raise WazuhInternalError(5002)

    return process_array(result, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)


def get_user_id(username: str = None, offset=0, limit=common.database_limit, sort_by=None,
              sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
    """Get the information of a specified user

    :param username: Name of the user
    :return: Information about user
    """
    with AuthenticationManager() as auth:
        result = auth.get_users(username)

    if not result or len(result) == 0:
        raise WazuhError(5001, extra_message='User {} does not exist'.format(username))

    return process_array(result, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)


def create_user(username: str = None, password: str = None):
    """Create a new user

    :param username: Name for the new user
    :param password: Password for the new user
    :return: Status message
    """
    if not _user_password.match(password):
        raise WazuhError(5007)

    result = None
    with AuthenticationManager() as auth:
        if auth.add_user(username, password):
            result = get_user_id(username)

    if result is None:
        raise WazuhError(5000, extra_message='The user \'{}\' could not be created'.format(username))

    return result


def update_user(username: str, password: str):
    """Update a specified user

    :param username: Name for the new user
    :param password: Password for the new user
    :return: Status message
    """
    if not _user_password.match(password):
        raise WazuhError(5007)

    with AuthenticationManager() as auth:
        query = auth.update_user(username, password)
        if query is True:
            return get_user_id(username)
        elif query is False:
            raise WazuhError(5001, extra_message='The user \'{}\' not exist'.format(username))
        elif query == 'admin':
            raise WazuhError(5004, extra_message='The users wazuh and wazuh-app can not be updated')


def delete_user(username: str):
    """Delete a specified user

    :param username: Name of the user
    :return: Status message
    """
    with AuthenticationManager() as auth:
        query = auth.delete_user(username)
        if query is True:
            return 'User \'{}\' deleted correctly'.format(username)
        elif query is False:
            raise WazuhError(5001, extra_message='The user \'{}\' not exist'.format(username))
        elif query == 'admin':
            raise WazuhError(5004, extra_message='The users wazuh and wazuh-app can not be removed')


@expose_resources(actions=['security:read'], resources=['role:id:{role_ids}'], target_param='role_ids')
def get_role(role_ids=None, offset=0, limit=common.database_limit, sort_by=None,
             sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
    """Returns information from all system roles, does not return information from its associated policies

    :param role_ids: List of roles ids.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    affected_items = list()
    failed_items = list()
    with orm.RolesManager() as rm:
        for r_id in role_ids:
            role = rm.get_role_id(int(r_id))
            if role != SecurityError.ROLE_NOT_EXIST:
                dict_role = role.to_dict()
                for index, policy in enumerate(dict_role['policies']):
                    dict_role['policies'][index]['policy'] = json.loads(dict_role['policies'][index]['policy'])
                affected_items.append(dict_role)
            else:
                # Role id does not exist
                failed_items.append(create_exception_dic(r_id, WazuhError(4002)))

    return process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)


@expose_resources(actions=['security:read'], resources=['role:id:*'], target_param='role_ids')
def get_roles(role_ids=None, offset=0, limit=common.database_limit, sort_by=None,
              sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
    """Returns information from all system roles, does not return information from its associated policies

    :param role_ids: List of roles ids. (All)
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    affected_items = list()
    with orm.RolesManager() as rm:
        for r_id in role_ids:
            role = rm.get_role_id(int(r_id))
            if role != SecurityError.ROLE_NOT_EXIST:
                dict_role = role.to_dict()
                dict_role.pop('policies', None)
                affected_items.append(dict_role)

    return process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)


@expose_resources(actions=['security:delete'], resources=['role:id:{role_ids}'], target_param='role_ids')
def remove_role(role_ids):
    """Removes a certain role from the system

    :param role_ids: List of roles ids.
    :return Result of operation.
    """
    affected_items = list()
    failed_items = list()
    with orm.RolesManager() as rm:
        for r_id in role_ids:
            result = rm.delete_role(int(r_id))
            if result == SecurityError.ADMIN_RESOURCES:
                failed_items.append(create_exception_dic(r_id, WazuhError(4008)))
            elif result is False:
                failed_items.append(create_exception_dic(r_id, WazuhError(4002)))
            else:
                affected_items.append(r_id)

    return "Roles {} correctly deleted".format(', '.join(affected_items))


@expose_resources(actions=['security:delete'], resources=['role:id:*'], target_param='role_ids')
def remove_roles(role_ids=None):
    """Removes a list of roles from the system

    :param role_ids: List of roles ids. (All)
    :return Result of operation.
    """
    affected_items = list()
    with orm.RolesManager() as rm:
        for r_id in role_ids:
            result = rm.delete_role(int(r_id))
            if result and result != SecurityError.ADMIN_RESOURCES:
                affected_items.append(r_id)

    return "Roles {} correctly deleted".format(', '.join(affected_items))


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


@expose_resources(actions=['security:update'], resources=['role:id:{role_id}'], target_param='role_id')
def update_role(role_id=None, name=None, rule=None):
    """Updates a role in the system

    :param role_id: Role id to be update
    :param name: The new role name
    :param rule: The new rule
    :return Role information.
    """
    if name is None and rule is None:
        raise WazuhError(4001)

    with orm.RolesManager() as rm:
        status = rm.update_role(role_id=role_id[0], name=name, rule=rule)
        if status == SecurityError.ALREADY_EXIST:
            raise WazuhError(4005)
        if status == SecurityError.INVALID:
            raise WazuhError(4003)
        if status == SecurityError.ROLE_NOT_EXIST:
            raise WazuhError(4002)

    return rm.get_role_id(role_id=role_id[0]).to_dict()


@expose_resources(actions=['security:read'], resources=['policy:id:{policy_id}'], target_param='policy_id')
def get_policy(policy_id, offset=0, limit=common.database_limit, sort_by=None,
               sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
    """Returns the information of a certain policy

    :param policy_id: ID of the policy on which the information will be collected
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    affected_items = list()
    failed_items = list()
    with orm.PoliciesManager() as pm:
        for p_id in policy_id:
            policy = pm.get_policy_id(int(p_id))
            if policy != SecurityError.POLICY_NOT_EXIST:
                dict_policy = policy.to_dict()
                if len(dict_policy['roles']) == 0:
                    dict_policy.pop('roles', None)
                else:
                    for index, policy in enumerate(dict_policy['roles']):
                        dict_policy['roles'][index]['rule'] = json.loads(dict_policy['roles'][index]['rule'])
                affected_items.append(dict_policy)
            else:
                # Policy id does not exist
                failed_items.append(create_exception_dic(p_id, WazuhError(4007)))

    return process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)


@expose_resources(actions=['security:read'], resources=['policy:id:*'], target_param='policy_id')
def get_policies(policy_id=None, offset=0, limit=common.database_limit, sort_by=None,
                 sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
    """Here we will be able to obtain all policies

    :param policy_id: Lists of IDs of the policies on which the information will be collected
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    affected_items = list()
    with orm.PoliciesManager() as pm:
        for p_id in policy_id:
            policy = pm.get_policy_id(int(p_id))
            if policy != SecurityError.POLICY_NOT_EXIST:
                dict_policy = policy.to_dict()
                dict_policy.pop('roles', None)
                affected_items.append(dict_policy)

    return process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields,
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

    return pm.get_policy_id(policy_id).to_dict()


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

    return get_role(role_ids=role_id)


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

    return get_role(role_ids=role_id)
