# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
from copy import deepcopy
from functools import lru_cache

import api.configuration as configuration
from wazuh.core import common
from wazuh.core.exception import WazuhError
from wazuh.core.results import AffectedItemsWazuhResult, WazuhResult
from wazuh.core.security import check_relationships, invalid_users_tokens, revoke_tokens
from wazuh.core.security import load_spec, update_security_conf
from wazuh.core.utils import process_array
from wazuh.rbac.decorators import expose_resources
from wazuh.rbac.orm import AuthenticationManager, PoliciesManager, RolesManager, RolesPoliciesManager, \
    TokenManager, UserRolesManager
from wazuh.rbac.orm import SecurityError, admin_role_ids, admin_policy_ids

# Minimum eight characters, at least one uppercase letter, one lowercase letter, one number and one special character:
_user_password = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[_@$!%*?&-])[A-Za-z\d@$!%*?&-_]{8,}$')


def get_user_me():
    """Get the information of the current user

    Returns
    -------
    AffectedItemsWazuhResult with the desired information
    """
    result = AffectedItemsWazuhResult(all_msg='Current user information was shown')
    affected_items = list()
    with AuthenticationManager() as auth:
        user = auth.get_user(common.current_user.get())
        for index, role_id in enumerate(user['roles']):
            with RolesManager() as rm:
                role = rm.get_role_id(role_id=role_id)
                role.pop('users')
                for index_p, policy_id in enumerate(role['policies']):
                    with PoliciesManager() as pm:
                        role['policies'][index_p] = pm.get_policy_id(policy_id=policy_id)
                        role['policies'][index_p].pop('roles')
                user['roles'][index] = role
        affected_items.append(user) if user else result.add_failed_item(id_=common.current_user.get(),
                                                                        error=WazuhError(5001))

    data = process_array(affected_items)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=['security:read'], resources=['user:id:{user_ids}'],
                  post_proc_kwargs={'exclude_codes': [5001]})
def get_users(user_ids: list = None, offset: int = 0, limit: int = common.database_limit, sort_by: dict = None,
              sort_ascending: bool = True, search_text: str = None,
              complementary_search: bool = False, search_in_fields: list = None):
    """Get the information of a specified user

    Parameters
    ----------
    user_ids : list
        List of user ids
    offset : int
        First item to return
    limit : int
        Maximum number of items to return
    sort_by : dict
        Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order
    search_text : str
        Text to search
    complementary_search : bool
        Find items without the text to search
    search_in_fields : list
        Fields to search in

    Returns
    -------
    AffectedItemsWazuhResult with the desired information
    """
    result = AffectedItemsWazuhResult(none_msg='No user was shown',
                                      some_msg='Some users could not be shown',
                                      all_msg='All specified users were shown')
    affected_items = list()
    with AuthenticationManager() as auth:
        for user_id in user_ids:
            user = auth.get_user_id(user_id)
            affected_items.append(user) if user else result.add_failed_item(id_=user_id, error=WazuhError(5001))

    data = process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=['security:create_user'], resources=['*:*:*'])
def create_user(username: str = None, password: str = None):
    """Create a new user

    :param username: Name for the new user
    :param password: Password for the new user
    :return: Status message
    """
    if not _user_password.match(password):
        raise WazuhError(5007)

    result = AffectedItemsWazuhResult(none_msg='User could not be created',
                                      all_msg='User created correctly')
    with AuthenticationManager() as auth:
        if auth.add_user(username, password):
            operation = auth.get_user(username)
            if operation:
                result.affected_items.append(operation)
                result.total_affected_items = 1
            else:
                result.add_failed_item(id_=username, error=WazuhError(5000))
        else:
            result.add_failed_item(id_=username, error=WazuhError(5000))

    return result


@expose_resources(actions=['security:update'], resources=['user:id:{user_id}'])
def update_user(user_id=None, password=None):
    """Update a specified user

    Parameters
    ----------
    user_id : str
        User ID
    password : str
        Password for the new user

    Returns
    -------
    Status message
    """
    if not _user_password.match(password):
        raise WazuhError(5007)
    result = AffectedItemsWazuhResult(all_msg='User modified correctly',
                                      none_msg='User could not be updated')
    with AuthenticationManager() as auth:
        query = auth.update_user(user_id[0], password)
        if not query:
            result.add_failed_item(id_=user_id[0], error=WazuhError(5001))
        else:
            result.affected_items.append(auth.get_user_id(user_id[0]))
            result.total_affected_items += 1
            invalid_users_tokens(users=[user_id[0]])

    return result


@expose_resources(actions=['security:delete'], resources=['user:id:{user_ids}'],
                  post_proc_kwargs={'exclude_codes': [5001, 5004, 5008]})
def remove_users(user_ids):
    """Remove a specified list of users

    Parameters
    ----------
    user_ids : list
        List of IDs

    Returns
    -------
    Status message
    """
    result = AffectedItemsWazuhResult(none_msg='No user was deleted',
                                      some_msg='Some users could not be deleted',
                                      all_msg='Users deleted correctly')
    with AuthenticationManager() as auth:
        for user_id in user_ids:
            current_user = auth.get_user(common.current_user.get())
            if not isinstance(current_user, bool) and int(user_id) == int(current_user['id']):
                result.add_failed_item(id_=user_id, error=WazuhError(5008))
                continue
            user = auth.get_user_id(user_id)
            query = auth.delete_user(user_id)
            if not query:
                result.add_failed_item(id_=user_id, error=WazuhError(5001))
            elif query == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=user_id, error=WazuhError(5004))
            elif user:
                result.affected_items.append(user)
                result.total_affected_items += 1
                invalid_users_tokens(users=[user_id])
        result.affected_items.sort(key=str)

    return result


@expose_resources(actions=['security:read'], resources=['role:id:{role_ids}'],
                  post_proc_kwargs={'exclude_codes': [4002]})
def get_roles(role_ids=None, offset=0, limit=common.database_limit, sort_by=None,
              sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
    """Returns information from all system roles, does not return information from its associated policies

    :param role_ids: List of roles ids (None for all roles)
    :param offset: First item to return
    :param limit: Maximum number of items to return
    :param sort_by: Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    affected_items = list()
    result = AffectedItemsWazuhResult(none_msg='No role were shown',
                                      some_msg='Some roles could not be shown',
                                      all_msg='All specified roles were shown')
    with RolesManager() as rm:
        for r_id in role_ids:
            role = rm.get_role_id(int(r_id))
            if role != SecurityError.ROLE_NOT_EXIST:
                affected_items.append(role)
            else:
                # Role id does not exist
                result.add_failed_item(id_=r_id, error=WazuhError(4002))

    data = process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=['security:delete'], resources=['role:id:{role_ids}'],
                  post_proc_kwargs={'exclude_codes': [4002, 4008]})
def remove_roles(role_ids):
    """Removes a certain role from the system

    :param role_ids: List of roles ids (None for all roles)
    :return Result of operation
    """
    result = AffectedItemsWazuhResult(none_msg='No role were deleted',
                                      some_msg='Some roles could not be delete',
                                      all_msg='All specified roles were deleted')
    with RolesManager() as rm:
        for r_id in role_ids:
            role = rm.get_role_id(int(r_id))
            if role != SecurityError.ROLE_NOT_EXIST and int(r_id) not in admin_role_ids:
                related_users = check_relationships([role])
            role_delete = rm.delete_role(int(r_id))
            if role_delete == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=r_id, error=WazuhError(4008))
            elif not role_delete:
                result.add_failed_item(id_=r_id, error=WazuhError(4002))
            elif role:
                result.affected_items.append(role)
                result.total_affected_items += 1
                invalid_users_tokens(users=list(related_users))
        result.affected_items = sorted(result.affected_items, key=lambda i: i['id'])

    return result


@expose_resources(actions=['security:create'], resources=['*:*:*'])
def add_role(name=None, rule=None):
    """Creates a role in the system

    :param name: The new role name
    :param rule: The new rule
    :return Role information
    """
    result = AffectedItemsWazuhResult(none_msg='Role could not be created',
                                      all_msg='Role created correctly')
    with RolesManager() as rm:
        status = rm.add_role(name=name, rule=rule)
        if status == SecurityError.ALREADY_EXIST:
            result.add_failed_item(id_=name, error=WazuhError(4005))
        elif status == SecurityError.INVALID:
            result.add_failed_item(id_=name, error=WazuhError(4003))
        else:
            result.affected_items.append(rm.get_role(name=name))
            result.total_affected_items += 1

    return result


@expose_resources(actions=['security:update'], resources=['role:id:{role_id}'])
def update_role(role_id=None, name=None, rule=None):
    """Updates a role in the system

    :param role_id: Role id to be update
    :param name: The new role name
    :param rule: The new rule
    :return Role information
    """
    if name is None and rule is None:
        raise WazuhError(4001)
    result = AffectedItemsWazuhResult(none_msg='Role could not be updated',
                                      all_msg='Role updated correctly')
    with RolesManager() as rm:
        status = rm.update_role(role_id=role_id[0], name=name, rule=rule)
        if status == SecurityError.ALREADY_EXIST:
            result.add_failed_item(id_=role_id[0], error=WazuhError(4005))
        elif status == SecurityError.INVALID:
            result.add_failed_item(id_=role_id[0], error=WazuhError(4003))
        elif status == SecurityError.ROLE_NOT_EXIST:
            result.add_failed_item(id_=role_id[0], error=WazuhError(4002))
        elif status == SecurityError.ADMIN_RESOURCES:
            result.add_failed_item(id_=role_id[0], error=WazuhError(4008))
        else:
            updated = rm.get_role_id(role_id[0])
            result.affected_items.append(updated)
            result.total_affected_items += 1
            invalid_users_tokens(roles=[updated])

    return result


@expose_resources(actions=['security:read'], resources=['policy:id:{policy_ids}'],
                  post_proc_kwargs={'exclude_codes': [4007]})
def get_policies(policy_ids, offset=0, limit=common.database_limit, sort_by=None,
                 sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
    """Returns the information of a certain policy

    :param policy_ids: ID of the policy on which the information will be collected (All for all policies)
    :param offset: First item to return
    :param limit: Maximum number of items to return
    :param sort_by: Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    result = AffectedItemsWazuhResult(none_msg='No policy were shown',
                                      some_msg='Some policies could not be shown',
                                      all_msg='All specified policies were shown')
    affected_items = list()
    with PoliciesManager() as pm:
        for p_id in policy_ids:
            policy = pm.get_policy_id(int(p_id))
            if policy != SecurityError.POLICY_NOT_EXIST:
                affected_items.append(policy)
            else:
                # Policy id does not exist
                result.add_failed_item(id_=p_id, error=WazuhError(4007))

    data = process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=['security:delete'], resources=['policy:id:{policy_ids}'],
                  post_proc_kwargs={'exclude_codes': [4007, 4008]})
def remove_policies(policy_ids=None):
    """Removes a certain policy from the system

    :param policy_ids: ID of the policy to be removed (All for all policies)
    :return Result of operation
    """
    result = AffectedItemsWazuhResult(none_msg='No policies were deleted',
                                      some_msg='Some policies could not be deleted',
                                      all_msg='All specified policies were deleted')
    with PoliciesManager() as pm:
        for p_id in policy_ids:
            policy = pm.get_policy_id(int(p_id))
            if policy != SecurityError.POLICY_NOT_EXIST and int(p_id) not in admin_policy_ids:
                related_users = check_relationships(policy['roles'])
            policy_delete = pm.delete_policy(int(p_id))
            if policy_delete == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=p_id, error=WazuhError(4008))
            elif not policy_delete:
                result.add_failed_item(id_=p_id, error=WazuhError(4007))
            elif policy:
                result.affected_items.append(policy)
                result.total_affected_items += 1
                invalid_users_tokens(users=list(related_users))
        result.affected_items = sorted(result.affected_items, key=lambda i: i['id'])

    return result


@expose_resources(actions=['security:create'], resources=['*:*:*'],
                  post_proc_kwargs={'exclude_codes': [4006, 4009]})
def add_policy(name=None, policy=None):
    """Creates a policy in the system

    :param name: The new policy name
    :param policy: The new policy
    :return Policy information
    """
    result = AffectedItemsWazuhResult(none_msg='Policy could not be created',
                                      all_msg='Policy created correctly')
    with PoliciesManager() as pm:
        status = pm.add_policy(name=name, policy=policy)
        if status == SecurityError.ALREADY_EXIST:
            result.add_failed_item(id_=name, error=WazuhError(4009))
        elif status == SecurityError.INVALID:
            result.add_failed_item(id_=name, error=WazuhError(4006))
        else:
            result.affected_items.append(pm.get_policy(name=name))
            result.total_affected_items += 1

    return result


@expose_resources(actions=['security:update'], resources=['policy:id:{policy_id}'])
def update_policy(policy_id=None, name=None, policy=None):
    """Updates a policy in the system

    :param policy_id: Policy id to be update
    :param name: The new policy name
    :param policy: The new policy
    :return Policy information
    """
    if name is None and policy is None:
        raise WazuhError(4001)
    result = AffectedItemsWazuhResult(none_msg='Policy could not be updated',
                                      all_msg='Policy updated correctly')
    with PoliciesManager() as pm:
        status = pm.update_policy(policy_id=policy_id[0], name=name, policy=policy)
        if status == SecurityError.ALREADY_EXIST:
            result.add_failed_item(id_=policy_id[0], error=WazuhError(4013))
        elif status == SecurityError.INVALID:
            result.add_failed_item(id_=policy_id[0], error=WazuhError(4006))
        elif status == SecurityError.POLICY_NOT_EXIST:
            result.add_failed_item(id_=policy_id[0], error=WazuhError(4007))
        elif status == SecurityError.ADMIN_RESOURCES:
            result.add_failed_item(id_=policy_id[0], error=WazuhError(4008))
        else:
            updated = pm.get_policy_id(policy_id[0])
            result.affected_items.append(updated)
            result.total_affected_items += 1
            invalid_users_tokens(roles=updated['roles'])

    return result


def get_username(user_id):
    """Return the username of the specified user_id

    Parameters
    ----------
    user_id : list
        User ID

    Returns
    -------
    username if the user_id exists, unknown in other case
    """
    with AuthenticationManager() as am:
        user = am.get_user_id(user_id=user_id[0])
        username = user['username'] if user else 'unknown'

    return username


@expose_resources(actions=['security:update'], resources=['user:id:{user_id}', 'role:id:{role_ids}'],
                  post_proc_kwargs={'exclude_codes': [4002, 4017, 4008, 5001]})
def set_user_role(user_id, role_ids, position=None):
    """Create a relationship between a user and a role.

    Parameters
    ----------
    user_id : list
        User ID
    role_ids : list of int
        List of role ids
    position : int
        Position where the new role will be inserted

    Returns
    -------
    Dict
        User-Roles information
    """
    if position is not None and position < 0:
        raise WazuhError(4018)

    username = get_username(user_id=user_id)
    result = AffectedItemsWazuhResult(none_msg=f'No link created to user {username}',
                                      some_msg=f'Some roles could not be linked to user {username}',
                                      all_msg=f'All roles were linked to user {username}')
    success = False
    with UserRolesManager() as urm:
        for role_id in role_ids:
            user_role = urm.add_role_to_user(user_id=user_id[0], role_id=role_id, position=position)
            if user_role == SecurityError.ALREADY_EXIST:
                result.add_failed_item(id_=role_id, error=WazuhError(4017))
            elif user_role == SecurityError.ROLE_NOT_EXIST:
                result.add_failed_item(id_=role_id, error=WazuhError(4002))
            elif user_role == SecurityError.USER_NOT_EXIST:
                result.add_failed_item(id_=user_id[0], error=WazuhError(5001))
                break
            elif user_role == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=user_id[0], error=WazuhError(4008))
            else:
                success = True
                result.total_affected_items += 1
                if position is not None:
                    position += 1
        if success:
            with AuthenticationManager() as auth:
                result.affected_items.append(auth.get_user_id(user_id[0]))
            result.affected_items.sort(key=str)
            invalid_users_tokens(users=[user_id[0]])

    return result


@expose_resources(actions=['security:delete'], resources=['user:id:{user_id}', 'role:id:{role_ids}'],
                  post_proc_kwargs={'exclude_codes': [4002, 4016, 4008, 5001]})
def remove_user_role(user_id, role_ids):
    """Create a relationship between a user and a role

    :param user_id: User id
    :param role_ids: List of role ids
    :return User-Roles information
    """
    username = get_username(user_id=user_id)
    result = AffectedItemsWazuhResult(none_msg=f'No role unlinked from user {username}',
                                      some_msg=f'Some roles could not be unlinked from user {username}',
                                      all_msg=f'All roles were unlinked from user {username}')
    success = False
    with UserRolesManager() as urm:
        for role_id in role_ids:
            user_role = urm.remove_role_in_user(user_id=user_id[0], role_id=role_id)
            if user_role == SecurityError.INVALID:
                result.add_failed_item(id_=role_id, error=WazuhError(4016))
            elif user_role == SecurityError.ROLE_NOT_EXIST:
                result.add_failed_item(id_=role_id, error=WazuhError(4002))
            elif user_role == SecurityError.USER_NOT_EXIST:
                result.add_failed_item(id_=user_id[0], error=WazuhError(5001))
                break
            elif user_role == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=user_id[0], error=WazuhError(4008))
            else:
                success = True
                result.total_affected_items += 1
        if success:
            with AuthenticationManager() as auth:
                result.affected_items.append(auth.get_user_id(user_id[0]))
            result.affected_items.sort(key=str)
            invalid_users_tokens(users=[user_id[0]])

    return result


@expose_resources(actions=['security:update'], resources=['role:id:{role_id}', 'policy:id:{policy_ids}'],
                  post_proc_kwargs={'exclude_codes': [4002, 4007, 4008, 4011]})
def set_role_policy(role_id, policy_ids, position=None):
    """Create a relationship between a role and a policy

    Parameters
    ----------
    role_id : int
        The new role_id
    policy_ids : list of int
        List of policy IDs
    position : int
        Position where the new role will be inserted

    Returns
    -------
    dict
        Role-Policies information
    """
    result = AffectedItemsWazuhResult(none_msg=f'No link created to role {role_id[0]}',
                                      some_msg=f'Some policies could not be linked to role {role_id[0]}',
                                      all_msg=f'All policies were linked to role {role_id[0]}')
    success = False
    with RolesPoliciesManager() as rpm:
        for policy_id in policy_ids:
            role_policy = rpm.add_policy_to_role(role_id=role_id[0], policy_id=policy_id, position=position)
            if role_policy == SecurityError.ALREADY_EXIST:
                result.add_failed_item(id_=policy_id, error=WazuhError(4011))
            elif role_policy == SecurityError.ROLE_NOT_EXIST:
                result.add_failed_item(id_=role_id[0], error=WazuhError(4002))
            elif role_policy == SecurityError.POLICY_NOT_EXIST:
                result.add_failed_item(id_=policy_id, error=WazuhError(4007))
            elif role_policy == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=role_id[0], error=WazuhError(4008))
            else:
                success = True
                result.total_affected_items += 1
                if position is not None:
                    position += 1
        if success:
            with RolesManager() as rm:
                result.affected_items.append(rm.get_role_id(role_id=role_id[0]))
                role = rm.get_role_id(role_id=role_id[0])
                invalid_users_tokens(roles=[role])
            result.affected_items.sort(key=str)

    return result


@expose_resources(actions=['security:delete'], resources=['role:id:{role_id}', 'policy:id:{policy_ids}'],
                  post_proc_kwargs={'exclude_codes': [4002, 4007, 4008, 4010]})
def remove_role_policy(role_id, policy_ids):
    """Removes a relationship between a role and a policy

    :param role_id: The new role_id
    :param policy_ids: List of policies ids
    :return Result of operation
    """
    result = AffectedItemsWazuhResult(none_msg=f'No policy unlinked from role {role_id[0]}',
                                      some_msg=f'Some policies could not be unlinked from role {role_id[0]}',
                                      all_msg=f'All policies were unlinked from role {role_id[0]}')
    success = False
    with RolesPoliciesManager() as rpm:
        for policy_id in policy_ids:
            role_policy = rpm.remove_policy_in_role(role_id=role_id[0], policy_id=policy_id)
            if role_policy == SecurityError.INVALID:
                result.add_failed_item(id_=policy_id, error=WazuhError(4010))
            elif role_policy == SecurityError.ROLE_NOT_EXIST:
                result.add_failed_item(id_=role_id[0], error=WazuhError(4002))
            elif role_policy == SecurityError.POLICY_NOT_EXIST:
                result.add_failed_item(id_=policy_id, error=WazuhError(4007))
            elif role_policy == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=role_id[0], error=WazuhError(4008))
            else:
                success = True
                result.total_affected_items += 1
        if success:
            with RolesManager() as rm:
                result.affected_items.append(rm.get_role_id(role_id=role_id[0]))
                role = rm.get_role_id(role_id=role_id[0])
                invalid_users_tokens(roles=[role])
            result.affected_items.sort(key=str)

    return result


def revoke_current_user_tokens():
    """Revoke all current user's tokens"""
    with TokenManager() as tm:
        tm.add_user_rules(users={common.current_user.get()})

    return WazuhResult({'msg': f'User {common.current_user.get()} logout correctly.'})


@expose_resources(actions=['security:revoke'], resources=['*:*:*'],
                  post_proc_kwargs={'default_result_kwargs': {
                      'none_msg': 'Permission denied in all manager nodes: Resource type: *:*'}})
def wrapper_revoke_tokens():
    """ Revoke all tokens """
    revoke_tokens()

    return WazuhResult({'msg': 'Tokens revoked successfully'})


@lru_cache(maxsize=None)
def get_api_endpoints():
    """Get a list with all API endpoints

    Returns
    -------
    list
        API endpoints
    """
    info_data = load_spec()
    endpoints_list = list()
    for path, path_info in info_data['paths'].items():
        for method in path_info.keys():
            endpoints_list.append(f'{method.upper()} {path}')

    return endpoints_list


@lru_cache(maxsize=None)
def get_rbac_resources(resource: str = None):
    """Get the RBAC resources from the catalog

    Parameters
    ----------
    resource : str
        Show the information of the specified resource. Ex: agent:id

    Returns
    -------
    dict
        RBAC resources
    """
    if not resource:
        return WazuhResult(load_spec()['x-rbac-catalog']['resources'])
    else:
        if resource not in load_spec()['x-rbac-catalog']['resources'].keys():
            raise WazuhError(4019)
        return WazuhResult({resource: load_spec()['x-rbac-catalog']['resources'][resource]})


@lru_cache(maxsize=None)
def get_rbac_actions(endpoint: str = None):
    """Get the RBAC actions from the catalog

    Parameters
    ----------
    endpoint : str
        Show actions and resources for the specified endpoint. Ex: GET /agents

    Returns
    -------
    dict
        RBAC resources
    """
    endpoints_list = get_api_endpoints()
    if endpoint and endpoint not in endpoints_list:
        raise WazuhError(4020, extra_remediation=endpoints_list)
    info_data = load_spec()
    data = dict()
    for path, path_info in info_data['paths'].items():
        for method, payload in path_info.items():
            try:
                for ref in payload['x-rbac-actions']:
                    action = list(ref.values())[0].split('/')[-1]
                    if endpoint and \
                            f'{method.upper()} {path}'.encode('ascii', 'ignore') != endpoint.encode('ascii', 'ignore'):
                        continue
                    if action not in data.keys():
                        data[action] = deepcopy(info_data['x-rbac-catalog']['actions'][action])
                    for index, resource in enumerate(info_data['x-rbac-catalog']['actions'][action]['resources']):
                        data[action]['resources'][index] = list(resource.values())[0].split('/')[-1]
                    if 'related_endpoints' not in data[action].keys():
                        data[action]['related_endpoints'] = list()
                    data[action]['related_endpoints'].append(f'{method.upper()} {path}')
            except KeyError:
                pass

    return WazuhResult(data)


@expose_resources(actions=['security:read_config'], resources=['*:*:*'])
def get_security_config():
    """Returns current security configuration."""
    return configuration.security_conf


@expose_resources(actions=['security:update_config'], resources=['*:*:*'])
def update_security_config(updated_config=None):
    """Update or restore current security configuration.

    Update the shared configuration object "security_conf" with
    "updated_config" and then overwrite the content of security.yaml.

    Parameters
    ----------
    updated_config : dict
        Dictionary with the new configuration.

    Returns
    -------
    result : str
        Confirmation/Error message.
    """
    try:
        update_security_conf(updated_config)
        result = 'Configuration successfully updated'
    except WazuhError as e:
        result = f'Configuration could not be updated. Error: {e}'

    return result
