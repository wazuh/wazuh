# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
from copy import deepcopy
from functools import lru_cache

from server_management_api.authentication import get_security_conf
from wazuh.core import common
from wazuh.core.exception import WazuhError, WazuhResourceNotFound
from wazuh.core.results import AffectedItemsWazuhResult, WazuhResult
from wazuh.core.security import invalid_users_tokens, invalid_roles_tokens, invalid_run_as_tokens, revoke_tokens, \
    load_spec, sanitize_rbac_policy, REQUIRED_FIELDS, SORT_FIELDS, SORT_FIELDS_GET_USERS
from wazuh.core.utils import process_array
from wazuh.rbac.decorators import expose_resources
from wazuh.rbac.orm import AuthenticationManager, PoliciesManager, RolesManager, RolesPoliciesManager
from wazuh.rbac.orm import SecurityError, MAX_ID_RESERVED
from wazuh.rbac.orm import UserRolesManager, RolesRulesManager, RulesManager
from wazuh.core.config.client import CentralizedConfig

# Minimum eight characters, at least one uppercase letter, one lowercase letter, one number and one special character:
_user_password = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$')


def get_user_me(token: dict) -> AffectedItemsWazuhResult:
    """Get the information of the current user.

    Parameters
    ----------
    token : dict
        Current token information.

    Returns
    -------
    AffectedItemsWazuhResult
        User information.
    """
    result = AffectedItemsWazuhResult(all_msg='Current user information was returned')
    affected_items = list()
    with AuthenticationManager() as auth:
        user_info = auth.get_user(token['sub'])
        user_info['roles'] = list()
    roles = token['rbac_roles']
    for role in roles:
        with RolesManager() as rm:
            role = rm.get_role_id(role_id=role)
            role.pop('users')
            for index_r, rule_id in enumerate(role['rules']):
                with RulesManager() as rum:
                    role['rules'][index_r] = rum.get_rule(rule_id=int(rule_id))
                    role['rules'][index_r].pop('roles')
            for index_p, policy_id in enumerate(role['policies']):
                with PoliciesManager() as pm:
                    role['policies'][index_p] = pm.get_policy_id(policy_id=int(policy_id))
                    role['policies'][index_p].pop('roles')
            user_info['roles'].append(role)

    affected_items.append(user_info) if user_info else result.add_failed_item(id_=common.current_user.get(),
                                                                              error=WazuhError(5001))
    data = process_array(affected_items)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=['security:read'], resources=['user:id:{user_ids}'],
                  post_proc_kwargs={'exclude_codes': [5001]})
async def get_users(user_ids: list = None, offset: int = 0, limit: int = common.DATABASE_LIMIT, sort_by: dict = None,
              sort_ascending: bool = True, search_text: str = None, select: str = None,
              complementary_search: bool = False, search_in_fields: list = None,
              q: str = None, distinct: bool = False) -> AffectedItemsWazuhResult:
    """Get the information of a specified user.

    Parameters
    ----------
    user_ids : list
        List of user ids.
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
    sort_by : dict
        Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order.
    search_text : str
        Text to search.
    select : str
        Select which fields to return (separated by comma).
    complementary_search : bool
        Find items without the text to search.
    search_in_fields : list
        Fields to search in.
    q : str
        Query to filter results by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    AffectedItemsWazuhResult
        User information.
    """
    result = AffectedItemsWazuhResult(none_msg='No user was returned',
                                      some_msg='Some users were not returned',
                                      all_msg='All specified users were returned')
    affected_items = list()
    with AuthenticationManager() as auth:
        for user_id in user_ids:
            user_id = int(user_id)
            user = auth.get_user_id(user_id)
            affected_items.append(user) if user else result.add_failed_item(id_=user_id, error=WazuhError(5001))

    data = process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields, select=select,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit, allowed_sort_fields=SORT_FIELDS_GET_USERS,
                         required_fields=REQUIRED_FIELDS, q=q, distinct=distinct)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=['security:edit_run_as'], resources=['*:*:*'])
async def edit_run_as(user_id: str = None, allow_run_as: bool = False) -> AffectedItemsWazuhResult:
    """Enable/Disable the user's allow_run_as flag.

    Parameters
    ----------
    user_id : str
        User ID.
    allow_run_as : bool
        Enable or disable authorization context login method for the specified user.

    Returns
    -------
    AffectedItemsWazuhResult
        Status message.
    """
    result = AffectedItemsWazuhResult(none_msg=f"The parameter allow_run_as could not be "
                                               f"{'enabled' if allow_run_as else 'disabled'} for the user",
                                      all_msg=f"Parameter allow_run_as has been "
                                              f"{'enabled' if allow_run_as else 'disabled'} for the user")
    with AuthenticationManager() as auth:
        user_id = int(user_id)
        query = auth.edit_run_as(user_id, allow_run_as)
        if query is False:
            result.add_failed_item(id_=user_id, error=WazuhError(5001))
        elif query == SecurityError.INVALID:
            result.add_failed_item(id_=user_id, error=WazuhError(5010))
        else:
            result.affected_items.append(auth.get_user_id(user_id))
            result.total_affected_items += 1
            invalid_users_tokens(users=[user_id])

    return result


@expose_resources(actions=['security:create_user'], resources=['*:*:*'])
async def create_user(username: str = None, password: str = None) -> AffectedItemsWazuhResult:
    """Create a new user.

    Parameters
    ----------
    username : str
        Name for the new user.
    password : str
        Password for the new user.

    Returns
    -------
    AffectedItemsWazuhResult
        Status message.
    """
    if len(password) > 64 or len(password) < 8:
        raise WazuhError(5009)
    elif not _user_password.match(password):
        raise WazuhError(5007)

    result = AffectedItemsWazuhResult(none_msg='User could not be created',
                                      all_msg='User was successfully created')
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
async def update_user(user_id: str = None, password: str = None, current_user: str = None) -> AffectedItemsWazuhResult:
    """Update a specified user

    Parameters
    ----------
    user_id : list
        User ID.
    password : str
        Password for the new user.
    current_user : str
        Name of the user that made the request.
    Raises
    ------
    WazuhError(4001)
        If no password is provided.
    WazuhError(5009)
        Insecure user password provided (length).
    WazuhError(5007)
        Insecure user password provided (variety of characters).

    Returns
    -------
    AffectedItemsWazuhResult
        Status message.
    """
    if password is None:
        raise WazuhError(4001)
    if password:
        if len(password) > 64 or len(password) < 8:
            raise WazuhError(5009)
        elif not _user_password.match(password):
            raise WazuhError(5007)

        if int(user_id[0]) <= MAX_ID_RESERVED and current_user is not None:
            with AuthenticationManager() as auth_manager:
                current_user_id = auth_manager.get_user(current_user)['id']

            if current_user_id > MAX_ID_RESERVED:
                raise WazuhError(5011)

    result = AffectedItemsWazuhResult(all_msg='User was successfully updated',
                                      none_msg='User could not be updated')
    with AuthenticationManager() as auth:
        query = auth.update_user(int(user_id[0]), password)
        if query is False:
            result.add_failed_item(id_=int(user_id[0]), error=WazuhError(5001))
        else:
            result.affected_items.append(auth.get_user_id(int(user_id[0])))
            result.total_affected_items += 1
            invalid_users_tokens(users=user_id)

    return result


@expose_resources(actions=['security:delete'], resources=['user:id:{user_ids}'],
                  post_proc_kwargs={'exclude_codes': [5001, 5004, 5008]})
async def remove_users(user_ids: list) -> AffectedItemsWazuhResult:
    """Remove a specified list of users.

    Parameters
    ----------
    user_ids : list
        List of IDs.

    Returns
    -------
    AffectedItemsWazuhResult
        Status message.
    """
    result = AffectedItemsWazuhResult(none_msg='No user was deleted',
                                      some_msg='Some users were not deleted',
                                      all_msg='Users were successfully deleted')
    with AuthenticationManager() as auth:
        for user_id in user_ids:
            user_id = int(user_id)
            current_user = auth.get_user(common.current_user.get())
            if not isinstance(current_user, bool) and user_id == int(current_user['id']) and user_id > MAX_ID_RESERVED:
                result.add_failed_item(id_=user_id, error=WazuhError(5008))
                continue
            user = auth.get_user_id(user_id)
            query = auth.delete_user(user_id)
            if not query:
                result.add_failed_item(id_=user_id, error=WazuhError(5001))
            elif query == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=user_id, error=WazuhError(5004))
            elif query == SecurityError.RELATIONSHIP_ERROR:
                result.add_failed_item(id_=user_id, error=WazuhError(4025))
            elif user:
                invalid_users_tokens(users=[user_id])
                result.affected_items.append(user)
                result.total_affected_items += 1

        result.affected_items.sort(key=str)
    return result


@expose_resources(actions=['security:read'], resources=['role:id:{role_ids}'],
                  post_proc_kwargs={'exclude_codes': [4002]})
async def get_roles(role_ids: list = None, offset: int = 0, limit: int = common.DATABASE_LIMIT, sort_by: dict = None,
              select: str = None, sort_ascending: bool = True, search_text: str = None,
              complementary_search: bool = False, search_in_fields: list = None,
              q: str = None, distinct: bool = False) -> AffectedItemsWazuhResult:
    """Return information from all system roles, does not return information from its associated policies.

    Parameters
    ----------
    role_ids : list, optional
        List of roles ids to be obtained.
    offset : int, optional
        First item to return.
    limit : int, optional
        Maximum number of items to return.
    sort_by : dict
        Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order.
    search_text : str
        Text to search.
    select : str
        Select which fields to return (separated by comma).
    complementary_search : bool
        Find items without the text to search.
    search_in_fields : list
        Fields to search in.
    q : str
        Query to filter results by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    AffectedItemsWazuhResult
        Roles information.
    """
    affected_items = list()
    result = AffectedItemsWazuhResult(none_msg='No role was returned',
                                      some_msg='Some roles were not returned',
                                      all_msg='All specified roles were returned')
    with RolesManager() as rm:
        for r_id in role_ids:
            role = rm.get_role_id(int(r_id))
            if role != SecurityError.ROLE_NOT_EXIST:
                affected_items.append(role)
            else:
                # Role id does not exist
                result.add_failed_item(id_=int(r_id), error=WazuhError(4002))

    data = process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields, select=select,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit, allowed_sort_fields=SORT_FIELDS, required_fields=REQUIRED_FIELDS,
                         q=q, distinct=distinct)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=['security:delete'], resources=['role:id:{role_ids}'],
                  post_proc_kwargs={'exclude_codes': [4002, 4008]})
async def remove_roles(role_ids: list) -> AffectedItemsWazuhResult:
    """Remove a certain role from the system.

    Parameters
    ----------
    role_ids : list
        List of role ids (None for all roles).

    Returns
    -------
    AffectedItemsWazuhResult
        Result of the operation.
    """
    result = AffectedItemsWazuhResult(none_msg='No role was deleted',
                                      some_msg='Some roles were not deleted',
                                      all_msg='All specified roles were deleted')
    with RolesManager() as rm:
        for r_id in role_ids:
            role = rm.get_role_id(int(r_id))
            role_delete = rm.delete_role(int(r_id))
            if role_delete == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=int(r_id), error=WazuhError(4008))
            elif role_delete == SecurityError.RELATIONSHIP_ERROR:
                result.add_failed_item(id_=int(r_id), error=WazuhError(4025))
            elif not role_delete:
                result.add_failed_item(id_=int(r_id), error=WazuhError(4002))
            elif role:
                result.affected_items.append(role)
                result.total_affected_items += 1

        invalid_roles_tokens(roles=[role['id'] for role in result.affected_items])
        result.affected_items = sorted(result.affected_items, key=lambda i: i['id'])

    return result


@expose_resources(actions=['security:create'], resources=['*:*:*'])
async def add_role(name: str = None) -> AffectedItemsWazuhResult:
    """Create a role in the system.

    Parameters
    ----------
    name : str
        New role name.

    Returns
    -------
    AffectedItemsWazuhResult
        Result of the operation.
    """
    result = AffectedItemsWazuhResult(none_msg='Role was not created',
                                      all_msg='Role was successfully created')
    with RolesManager() as rm:
        status = rm.add_role(name=name)
        if status == SecurityError.ALREADY_EXIST:
            result.add_failed_item(id_=name, error=WazuhError(4005))
        elif status == SecurityError.INVALID:
            result.add_failed_item(id_=name, error=WazuhError(4003))
        else:
            result.affected_items.append(rm.get_role(name=name))
            result.total_affected_items += 1

    return result


@expose_resources(actions=['security:update'], resources=['role:id:{role_id}'])
async def update_role(role_id: str = None, name: str = None) -> AffectedItemsWazuhResult:
    """Update a role in the system.

    Parameters
    ----------
    role_id : str
        Role ID.
    name : str
        New role name.

    Raises
    ------
    WazuhError(4001)
        If no name is provided.

    Returns
    -------
    AffectedItemsWazuhResult
        Result of the operation.
    """
    if name is None:
        raise WazuhError(4001)
    result = AffectedItemsWazuhResult(none_msg='Role was not updated',
                                      all_msg='Role was successfully updated')
    with RolesManager() as rm:
        status = rm.update_role(role_id=role_id[0], name=name)
        if status == SecurityError.ALREADY_EXIST:
            result.add_failed_item(id_=int(role_id[0]), error=WazuhError(4005))
        elif status == SecurityError.INVALID:
            result.add_failed_item(id_=int(role_id[0]), error=WazuhError(4003))
        elif status == SecurityError.ROLE_NOT_EXIST:
            result.add_failed_item(id_=int(role_id[0]), error=WazuhError(4002))
        elif status == SecurityError.ADMIN_RESOURCES:
            result.add_failed_item(id_=int(role_id[0]), error=WazuhError(4008))
        else:
            updated = rm.get_role_id(int(role_id[0]))
            result.affected_items.append(updated)
            result.total_affected_items += 1
            invalid_roles_tokens(roles=role_id)

    return result


@expose_resources(actions=['security:read'], resources=['policy:id:{policy_ids}'],
                  post_proc_kwargs={'exclude_codes': [4007]})
async def get_policies(policy_ids: list, offset: int = 0, limit: int = common.DATABASE_LIMIT, sort_by: dict = None,
                 select: str = None, sort_ascending: bool = True, search_text: str = None,
                 complementary_search: bool = False, search_in_fields: list = None,
                 q: str = None, distinct: bool = False) -> AffectedItemsWazuhResult:
    """Return the information of a certain policy.

    Parameters
    ----------
    policy_ids : list
        ID of the policy on which the information will be collected (All for all policies).
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
    sort_by : dict
        Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order.
    search_text : str
        Text to search.
    select : str
        Select which fields to return (separated by comma).
    complementary_search : bool
        Find items without the text to search.
    search_in_fields : list
        Fields to search in.
    q : str
        Query to filter results by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    AffectedItemsWazuhResult
        Policies information.
    """
    result = AffectedItemsWazuhResult(none_msg='No policy was returned',
                                      some_msg='Some policies were not returned',
                                      all_msg='All specified policies were returned')
    affected_items = list()
    with PoliciesManager() as pm:
        for p_id in policy_ids:
            policy = pm.get_policy_id(int(p_id))
            if policy != SecurityError.POLICY_NOT_EXIST:
                affected_items.append(policy)
            else:
                # Policy id does not exist
                result.add_failed_item(id_=int(p_id), error=WazuhError(4007))

    data = process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields, select=select,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit, allowed_sort_fields=SORT_FIELDS, required_fields=REQUIRED_FIELDS,
                         q=q, distinct=distinct)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=['security:delete'], resources=['policy:id:{policy_ids}'],
                  post_proc_kwargs={'exclude_codes': [4007, 4008]})
async def remove_policies(policy_ids: list = None) -> AffectedItemsWazuhResult:
    """Remove policies from the system.

    Parameters
    ----------
    policy_ids : list
        IDs of the policies to be removed (All for all policies).

    Returns
    -------
    AffectedItemsWazuhResult
        Result of operation.
    """
    result = AffectedItemsWazuhResult(none_msg='No policy was deleted',
                                      some_msg='Some policies were not deleted',
                                      all_msg='All specified policies were deleted')
    with PoliciesManager() as pm:
        for p_id in policy_ids:
            policy = pm.get_policy_id(int(p_id))
            policy_delete = pm.delete_policy(int(p_id))
            if policy_delete == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=int(p_id), error=WazuhError(4008))
            elif policy_delete == SecurityError.RELATIONSHIP_ERROR:
                result.add_failed_item(id_=int(p_id), error=WazuhError(4025))
            elif not policy_delete:
                result.add_failed_item(id_=int(p_id), error=WazuhError(4007))
            elif policy:
                result.affected_items.append(policy)
                result.total_affected_items += 1
                invalid_roles_tokens(roles=policy['roles'])

        result.affected_items = sorted(result.affected_items, key=lambda i: i['id'])

    return result


@expose_resources(actions=['security:create'], resources=['*:*:*'],
                  post_proc_kwargs={'exclude_codes': [4006, 4009]})
async def add_policy(name: str = None, policy: dict = None) -> AffectedItemsWazuhResult:
    """Create a policy in the system.

    Parameters
    ----------
    policy : dict
        New policy.
    name : str
        New policy name.

    Returns
    -------
    AffectedItemsWazuhResult
        Result of the operation.
    """
    result = AffectedItemsWazuhResult(none_msg='Policy was not created',
                                      all_msg='Policy was successfully created')
    sanitize_rbac_policy(policy)
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
async def update_policy(policy_id: str = None, name: str = None, policy: dict = None) -> AffectedItemsWazuhResult:
    """Update a policy in the system

    Parameters
    ----------
    policy_id : str
        Policy id to be updated.
    policy : dict
        New policy.
    name : str
        New policy name.

    Raises
    ------
    WazuhError(4001)
        If no name nor policy are provided.

    Returns
    -------
    AffectedItemsWazuhResult
        Result of the operation.
    """
    if name is None and policy is None:
        raise WazuhError(4001)
    result = AffectedItemsWazuhResult(none_msg='Policy was not updated',
                                      all_msg='Policy was successfully updated')
    policy is not None and sanitize_rbac_policy(policy)
    with PoliciesManager() as pm:
        status = pm.update_policy(policy_id=policy_id[0], name=name, policy=policy)
        if status == SecurityError.ALREADY_EXIST:
            result.add_failed_item(id_=int(policy_id[0]), error=WazuhError(4013))
        elif status == SecurityError.INVALID:
            result.add_failed_item(id_=int(policy_id[0]), error=WazuhError(4006))
        elif status == SecurityError.POLICY_NOT_EXIST:
            result.add_failed_item(id_=int(policy_id[0]), error=WazuhError(4007))
        elif status == SecurityError.ADMIN_RESOURCES:
            result.add_failed_item(id_=int(policy_id[0]), error=WazuhError(4008))
        else:
            updated = pm.get_policy_id(int(policy_id[0]))
            result.affected_items.append(updated)
            result.total_affected_items += 1
            invalid_roles_tokens(roles=updated['roles'])

    return result


@expose_resources(actions=['security:read'], resources=['rule:id:{rule_ids}'],
                  post_proc_kwargs={'exclude_codes': [4022]})
async def get_rules(rule_ids: list = None, offset: int = 0, limit: int = common.DATABASE_LIMIT, sort_by: dict = None,
              select: str = None, sort_ascending: bool = True, search_text: str = None,
              complementary_search: bool = False, search_in_fields: list = None,
              q: str = '', distinct: bool = False) -> AffectedItemsWazuhResult:
    """Return information from all the security rules. It does not return information from its associated roles.

    Parameters
    ----------
    rule_ids : list
        List of rule ids (None for all rules).
    offset : int
        First item to return.
    limit : int, optional
        Maximum number of items to return.
    sort_by : dict
        Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order.
    search_text : str
        Text to search.
    select : str
        Select which fields to return (separated by comma).
    complementary_search : bool
        Find items without the text to search.
    search_in_fields : list
        Fields to search in.
    q : str
        Query to filter results by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    AffectedItemsWazuhResult
        Rules information.
    """
    affected_items = list()
    result = AffectedItemsWazuhResult(none_msg='No security rule was returned',
                                      some_msg='Some security rules were not returned',
                                      all_msg='All specified security rules were returned')

    with RulesManager() as rum:
        for ru_id in rule_ids:
            rule = rum.get_rule(int(ru_id))
            if rule != SecurityError.RULE_NOT_EXIST:
                affected_items.append(rule)
            else:
                # Rule id does not exist
                result.add_failed_item(id_=ru_id, error=WazuhError(4022))

    data = process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields, select=select,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit, allowed_sort_fields=SORT_FIELDS, required_fields=REQUIRED_FIELDS,
                         q=q, distinct=distinct)
    result.affected_items = data['items']
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=['security:create'], resources=['*:*:*'])
async def add_rule(name: str = None, rule: dict = None) -> AffectedItemsWazuhResult:
    """Create a rule in the system.

    Parameters
    ----------
    rule : dict
        New rule.
    name : str
        New rule name.

    Returns
    -------
    AffectedItemsWazuhResult
        Result of the operation.
    """
    result = AffectedItemsWazuhResult(none_msg='Security rule was not created',
                                      all_msg='Security rule was successfully created')
    with RulesManager() as rum:
        status = rum.add_rule(name=name, rule=rule)
        if status == SecurityError.ALREADY_EXIST:
            result.add_failed_item(id_=name, error=WazuhError(4005))
        elif status == SecurityError.INVALID:
            result.add_failed_item(id_=name, error=WazuhError(4003))
        else:
            result.affected_items.append(rum.get_rule_by_name(name))
            result.total_affected_items += 1

    return result


@expose_resources(actions=['security:delete'], resources=['rule:id:{rule_ids}'],
                  post_proc_kwargs={'exclude_codes': [4022, 4008]})
async def remove_rules(rule_ids: list = None) -> AffectedItemsWazuhResult:
    """Remove a rule from the system.

    Parameters
    ----------
    rule_ids
        Listo of rule ids (None for all rules).

    Returns
    -------
    AffectedItemsWazuhResult
        Result of the operation.
    """
    result = AffectedItemsWazuhResult(none_msg='No security rule was deleted',
                                      some_msg='Some security rules were not deleted',
                                      all_msg='All specified security rules were deleted')
    with RulesManager() as rum:
        for r_id in rule_ids:
            rule = rum.get_rule(int(r_id))
            role_delete = rum.delete_rule(int(r_id))
            if role_delete == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=int(r_id), error=WazuhError(4008))
            elif role_delete == SecurityError.RELATIONSHIP_ERROR:
                result.add_failed_item(id_=int(r_id), error=WazuhError(4025))
            elif not role_delete:
                result.add_failed_item(id_=int(r_id), error=WazuhError(4022))
            elif rule:
                result.affected_items.append(rule)
                result.total_affected_items += 1
                invalid_roles_tokens(roles=rule['roles'])

        result.affected_items = sorted(result.affected_items, key=lambda i: i['id'])

    return result


@expose_resources(actions=['security:update'], resources=['rule:id:{rule_id}'])
async def update_rule(rule_id: str = None, name: str = None, rule: dict = None) -> AffectedItemsWazuhResult:
    """Update a rule from the system.

    Parameters
    ----------
    rule_id : str
        Rule id to be updated.
    rule : dict
        New rule.
    name : str
        New rule name.

    Raises
    ------
    WazuhError(4001)
        If no name nor rule are provided.

    Returns
    -------
    AffectedItemsWazuhResult
        Result of the operation.
    """
    if name is None and rule is None:
        raise WazuhError(4001)
    result = AffectedItemsWazuhResult(none_msg='Security rule was not updated',
                                      all_msg='Security rule was successfully updated')
    with RulesManager() as rum:
        status = rum.update_rule(rule_id=rule_id[0], name=name, rule=rule)
        if status == SecurityError.ALREADY_EXIST:
            result.add_failed_item(id_=int(rule_id[0]), error=WazuhError(4005))
        elif status == SecurityError.INVALID:
            result.add_failed_item(id_=int(rule_id[0]), error=WazuhError(4003))
        elif status == SecurityError.RULE_NOT_EXIST:
            result.add_failed_item(id_=int(rule_id[0]), error=WazuhError(4022))
        elif status == SecurityError.ADMIN_RESOURCES:
            result.add_failed_item(id_=int(rule_id[0]), error=WazuhError(4008))
        else:
            updated = rum.get_rule(rule_id[0])
            result.affected_items.append(updated)
            result.total_affected_items += 1
            invalid_roles_tokens(roles=updated['roles'])

    return result


def get_username(user_id: str) -> AffectedItemsWazuhResult:
    """Return the username of the specified user_id.

    Parameters
    ----------
    user_id : str
        User ID

    Returns
    -------
    AffectedItemsWazuhResult
        Username if the user_id exists, unknown in other case.
    """
    with AuthenticationManager() as am:
        user = am.get_user_id(user_id=int(user_id[0]))
        username = user['username'] if user else 'unknown'

    return username


@expose_resources(actions=['security:update'], resources=['user:id:{user_id}', 'role:id:{role_ids}'],
                  post_proc_kwargs={'exclude_codes': [4002, 4017, 4008, 5001]})
async def set_user_role(user_id: list, role_ids: list, position: int = None) -> AffectedItemsWazuhResult:
    """Create a relationship between a user and a role.

    Parameters
    ----------
    user_id : list
        User ID.
    role_ids : list
        List of role ids.
    position : int
        Position where the new role will be inserted.

    Raises
    ------
    WazuhError(4018)
        If position is a negative number.

    Returns
    -------
    AffectedItemsWazuhResult
        User-Roles information.
    """
    if position is not None and position < 0:
        raise WazuhError(4018)

    username = get_username(user_id=user_id)
    result = AffectedItemsWazuhResult(none_msg=f'No link was created to user {username}',
                                      some_msg=f'Some roles were not linked to user {username}',
                                      all_msg=f'All roles were linked to user {username}')
    success = False
    with UserRolesManager() as urm:
        for role_id in role_ids:
            user_role = urm.add_role_to_user(user_id=int(user_id[0]), role_id=int(role_id), position=position)
            if user_role == SecurityError.ALREADY_EXIST:
                result.add_failed_item(id_=int(role_id), error=WazuhError(4017))
            elif user_role == SecurityError.ROLE_NOT_EXIST:
                result.add_failed_item(id_=int(role_id), error=WazuhError(4002))
            elif user_role == SecurityError.USER_NOT_EXIST:
                result.add_failed_item(id_=int(user_id[0]), error=WazuhError(5001))
                break
            elif user_role == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=int(user_id[0]), error=WazuhError(4008))
            else:
                success = True
                result.total_affected_items += 1
                if position is not None:
                    position += 1
        if success:
            with AuthenticationManager() as auth:
                result.affected_items.append(auth.get_user_id(int(user_id[0])))
            result.affected_items.sort(key=str)
            invalid_users_tokens(users=user_id)

    return result


@expose_resources(actions=['security:delete'], resources=['user:id:{user_id}'],
                  post_proc_func=None)
@expose_resources(actions=['security:delete'], resources=['role:id:{role_ids}'],
                  post_proc_kwargs={'exclude_codes': [4002, 4016, 4008]})
async def remove_user_role(user_id: str, role_ids: list) -> AffectedItemsWazuhResult:
    """Remove a relationship between a user and a role.

    Parameters
    ----------
    user_id : list
        User ID.
    role_ids : list
        List of role ids.

    Raises
    ------
    WazuhResourceNotFound(5001)
        If the user does not exist.

    Returns
    -------
    AffectedItemsWazuhResult
        User-Roles information.
    """
    username = get_username(user_id=user_id)
    if username == 'unknown':
        raise WazuhResourceNotFound(5001)

    result = AffectedItemsWazuhResult(none_msg=f'No role was unlinked from user {username}',
                                      some_msg=f'Some roles were not unlinked from user {username}',
                                      all_msg=f'All roles were unlinked from user {username}')
    success = False
    with UserRolesManager() as urm:
        for role_id in role_ids:
            user_role = urm.remove_role_in_user(user_id=int(user_id[0]), role_id=role_id)
            if user_role == SecurityError.INVALID:
                result.add_failed_item(id_=int(role_id), error=WazuhError(4016))
            elif user_role == SecurityError.ROLE_NOT_EXIST:
                result.add_failed_item(id_=int(role_id), error=WazuhError(4002))
            elif user_role == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=int(user_id[0]), error=WazuhError(4008))
            else:
                success = True
                result.total_affected_items += 1
        if success:
            with AuthenticationManager() as auth:
                result.affected_items.append(auth.get_user_id(int(user_id[0])))
            result.affected_items.sort(key=str)
            invalid_users_tokens(users=user_id)

    return result


@expose_resources(actions=['security:update'], resources=['role:id:{role_id}', 'rule:id:{rule_ids}'],
                  post_proc_kwargs={'exclude_codes': [4002, 4008, 4022, 4023]})
async def set_role_rule(role_id: str, rule_ids: list, run_as: bool = False) -> AffectedItemsWazuhResult:
    """Create a relationship between a role and one or more rules.

    Parameters
    ----------
    role_id : str
        The new role_id.
    rule_ids : list
        List of rule ids.
    run_as : dict
        Login with an authorization context or not.

    Returns
    -------
    AffectedItemsWazuhResult
        Result of the operation.
    """

    result = AffectedItemsWazuhResult(none_msg=f'No link was created to role {role_id[0]}',
                                      some_msg=f'Some security rules were not linked to role {role_id[0]}',
                                      all_msg=f'All security rules were linked to role {role_id[0]}')
    success = False
    with RolesRulesManager() as rrm:
        for rule_id in rule_ids:
            role_rule = rrm.add_rule_to_role(role_id=int(role_id[0]), rule_id=int(rule_id))
            if role_rule == SecurityError.ALREADY_EXIST:
                result.add_failed_item(id_=int(rule_id), error=WazuhError(4023))
            elif role_rule == SecurityError.ROLE_NOT_EXIST:
                result.add_failed_item(id_=int(role_id[0]), error=WazuhError(4002))
            elif role_rule == SecurityError.RULE_NOT_EXIST:
                result.add_failed_item(id_=int(rule_id), error=WazuhError(4022))
            elif role_rule == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=int(role_id[0]), error=WazuhError(4008))
            else:
                success = True
                result.total_affected_items += 1
        if success:
            with RolesManager() as rm:
                result.affected_items.append(rm.get_role_id(role_id=role_id[0]))
                # Invalidate users with auth_context
                invalid_run_as_tokens()
            result.affected_items.sort(key=str)

    return result


@expose_resources(actions=['security:delete'], resources=['role:id:{role_id}'],
                  post_proc_func=None)
@expose_resources(actions=['security:delete'], resources=['rule:id:{rule_ids}'],
                  post_proc_kwargs={'exclude_codes': [4008, 4022, 4024]})
async def remove_role_rule(role_id: str, rule_ids: list) -> AffectedItemsWazuhResult:
    """Remove a relationship between a role and one or more rules.

    Parameters
    ----------
    role_id : str
        The new role_id.
    rule_ids : list
        List of rule ids.

    Raises
    ------
    WazuhResourceNotFound(4002)
        If the role does not exist.

    Returns
    -------
    AffectedItemsWazuhResult
        Result of the operation.
    """

    role = get_role(role_id[0])

    if not role:
        raise WazuhResourceNotFound(4002)

    result = AffectedItemsWazuhResult(none_msg=f'No security rule was unlinked from role {role_id[0]}',
                                      some_msg=f'Some security rules were not unlinked from role {role_id[0]}',
                                      all_msg=f'All security rules were unlinked from role {role_id[0]}')
    success = False
    with RolesRulesManager() as rrm:
        for rule_id in rule_ids:
            role_rule = rrm.remove_rule_in_role(role_id=int(role_id[0]), rule_id=int(rule_id))
            if role_rule == SecurityError.INVALID:
                result.add_failed_item(id_=rule_id, error=WazuhError(4024))
            elif role_rule == SecurityError.RULE_NOT_EXIST:
                result.add_failed_item(id_=rule_id, error=WazuhError(4022))
            elif role_rule == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=int(role_id[0]), error=WazuhError(4008))
            else:
                success = True
                result.total_affected_items += 1
        if success:
            with RolesManager() as rm:
                result.affected_items.append(rm.get_role_id(role_id=role_id[0]))
                # Invalidate users with auth_context
                invalid_run_as_tokens()
            result.affected_items.sort(key=str)

    return result


@expose_resources(actions=['security:update'], resources=['role:id:{role_id}', 'policy:id:{policy_ids}'],
                  post_proc_kwargs={'exclude_codes': [4002, 4007, 4008, 4011]})
async def set_role_policy(role_id: str, policy_ids: list, position: int = None) -> AffectedItemsWazuhResult:
    """Create a relationship between a role and a policy.

    Parameters
    ----------
    role_id : str
        The new role_id.
    policy_ids : list
        List of policy IDs.
    position : int
        Position where the new role will be inserted.

    Returns
    -------
    AffectedItemsWazuhResult
        Role-Policies information.
    """
    result = AffectedItemsWazuhResult(none_msg=f'No link was created to role {role_id[0]}',
                                      some_msg=f'Some policies were not linked to role {role_id[0]}',
                                      all_msg=f'All policies were linked to role {role_id[0]}')
    success = False
    with RolesPoliciesManager() as rpm:
        for policy_id in policy_ids:
            policy_id = int(policy_id)
            role_policy = rpm.add_policy_to_role(role_id=role_id[0], policy_id=policy_id, position=position)
            if role_policy == SecurityError.ALREADY_EXIST:
                result.add_failed_item(id_=policy_id, error=WazuhError(4011))
            elif role_policy == SecurityError.ROLE_NOT_EXIST:
                result.add_failed_item(id_=int(role_id[0]), error=WazuhError(4002))
            elif role_policy == SecurityError.POLICY_NOT_EXIST:
                result.add_failed_item(id_=policy_id, error=WazuhError(4007))
            elif role_policy == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=int(role_id[0]), error=WazuhError(4008))
            else:
                success = True
                result.total_affected_items += 1
                if position is not None:
                    position += 1
        if success:
            with RolesManager() as rm:
                result.affected_items.append(rm.get_role_id(role_id=role_id[0]))
                role = rm.get_role_id(role_id=role_id[0])
                invalid_roles_tokens(roles=[role['id']])
            result.affected_items.sort(key=str)

    return result


def get_role(role_id: str) -> bool:
    """Return the role name of the specified role_id.

    Parameters
    ----------
    role_id : str
        Role ID.

    Returns
    -------
    bool
        True if the role_id exists, False otherwise.
    """

    role_check = False

    with RolesManager() as rm:
        role_information = rm.get_role_id(int(role_id))
        if role_information != SecurityError.ROLE_NOT_EXIST:
            role_check = True

    return role_check


@expose_resources(actions=['security:delete'], resources=['role:id:{role_id}'],
                  post_proc_func=None)
@expose_resources(actions=['security:delete'], resources=['policy:id:{policy_ids}'],
                  post_proc_kwargs={'exclude_codes': [4007, 4008, 4010]})
async def remove_role_policy(role_id: str, policy_ids: list) -> AffectedItemsWazuhResult:
    """Remove a relationship between a role and a policy

    Parameters
    ----------
    role_id : str
        The new role_id.
    policy_ids : list
        List of policy IDs.

    Raises
    ------
    WazuhResourceNotFound(4002)
        If the role does not exist.

    Returns
    -------
    AffectedItemsWazuhResult
         Result of operation.
    """

    role = get_role(role_id[0])

    if not role:
        raise WazuhResourceNotFound(4002)

    result = AffectedItemsWazuhResult(none_msg=f'No policy was unlinked from role {role_id[0]}',
                                      some_msg=f'Some policies were not unlinked from role {role_id[0]}',
                                      all_msg=f'All policies were unlinked from role {role_id[0]}')
    success = False
    with RolesPoliciesManager() as rpm:
        for policy_id in policy_ids:
            policy_id = int(policy_id)
            role_policy = rpm.remove_policy_in_role(role_id=role_id[0], policy_id=policy_id)
            if role_policy == SecurityError.INVALID:
                result.add_failed_item(id_=policy_id, error=WazuhError(4010))
            elif role_policy == SecurityError.POLICY_NOT_EXIST:
                result.add_failed_item(id_=policy_id, error=WazuhError(4007))
            elif role_policy == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=int(role_id[0]), error=WazuhError(4008))
            else:
                success = True
                result.total_affected_items += 1
        if success:
            with RolesManager() as rm:
                result.affected_items.append(rm.get_role_id(role_id=role_id[0]))
                role = rm.get_role_id(role_id=role_id[0])
                invalid_roles_tokens(roles=[role['id']])
            result.affected_items.sort(key=str)

    return result


def revoke_current_user_tokens() -> WazuhResult:
    """Revoke all current user's tokens.

    Returns
    -------
    WazuhResult
         Result of operation.
    """
    with AuthenticationManager() as am:
        invalid_users_tokens(users=[am.get_user(common.current_user.get())['id']])

    return WazuhResult({'message': f'User {common.current_user.get()} was successfully logged out'})


@expose_resources(actions=['security:revoke'], resources=['*:*:*'],
                  post_proc_kwargs={'default_result_kwargs': {
                      'none_msg': 'Permission denied in all manager nodes: Resource type: *:*'}})
async def wrapper_revoke_tokens() -> WazuhResult:
    """Revoke all tokens.

    Returns
    -------
    WazuhResult
         Result of operation.
    """
    revoke_tokens()

    return WazuhResult({'message': 'Tokens were successfully revoked'})


@lru_cache(maxsize=None)
def get_api_endpoints() -> list:
    """Get a list with all API endpoints.

    Returns
    -------
    list
        API endpoints.
    """
    info_data = load_spec()
    endpoints_list = list()
    for path, path_info in info_data['paths'].items():
        for method in path_info.keys():
            endpoints_list.append(f'{method.upper()} {path}')

    return endpoints_list


@lru_cache(maxsize=None)
def get_rbac_resources(resource: str = None) -> WazuhResult:
    """Get the RBAC resources from the catalog.

    Parameters
    ----------
    resource : str
        Show the information of the specified resource. Ex: agent:id

    Raises
    ------
    WazuhError(4019)
        If no resource is specified.

    Returns
    -------
    WazuhResult
        RBAC resources.
    """
    if not resource:
        return WazuhResult({'data': load_spec()['x-rbac-catalog']['resources']})
    else:
        if resource not in load_spec()['x-rbac-catalog']['resources'].keys():
            raise WazuhError(4019)
        return WazuhResult({'data': {resource: load_spec()['x-rbac-catalog']['resources'][resource]}})


@lru_cache(maxsize=None)
def get_rbac_actions(endpoint: str = None) -> WazuhResult:
    """Get the RBAC actions from the catalog.

    Parameters
    ----------
    endpoint : str
        Show actions and resources for the specified endpoint. Ex: GET /agents

    Raises
    ------
    WazuhError(4020)
        Invalid endpoint specified.

    Returns
    -------
    WazuhResult
        RBAC actions.
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

    return WazuhResult({'data': data})


@expose_resources(actions=['security:read_config'], resources=['*:*:*'])
async def get_security_config() -> WazuhResult:
    """Return current security configuration.

    Returns
    -------
    WazuhResult
        Security information.
    """
    return WazuhResult({'data': get_security_conf()})


@expose_resources(actions=['security:update_config'], resources=['*:*:*'])
async def update_security_config(updated_config: dict = None) -> str:
    """Update or restore current security configuration.

    Update the shared configuration object "security_conf" with
    "updated_config" and then overwrite the content of security.yaml.

    Parameters
    ----------
    updated_config : dict
        Dictionary with the new configuration.

    Returns
    -------
    str
        Confirmation/Error message.
    """
    try:
        CentralizedConfig.update_security_conf(config=updated_config)
        result = 'Configuration was successfully updated'
    except WazuhError as e:
        result = f'Configuration could not be updated. Error: {e}'

    return result
