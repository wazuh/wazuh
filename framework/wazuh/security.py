# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import re

from api.authentication import AuthenticationManager, validation
from wazuh import common
from wazuh.exception import WazuhError
from wazuh.rbac import orm
from wazuh.rbac.decorators import expose_resources
from wazuh.rbac.orm import SecurityError
from wazuh.results import AffectedItemsWazuhResult, WazuhResult
from wazuh.utils import process_array
from time import time

# Minimum eight characters, at least one uppercase letter, one lowercase letter, one number and one special character:
_user_password = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[_@$!%*?&-])[A-Za-z\d@$!%*?&-_]{8,}$')


@expose_resources(actions=['security:read'], resources=['user:id:{username_list}'],
                  post_proc_kwargs={'exclude_codes': [5001]})
def get_users(username_list=None, offset=0, limit=common.database_limit, sort_by=None,
              sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None):
    """Get the information of a specified user

    :param username_list: Name of the user (None for all users)
    :param offset: First item to return
    :param limit: Maximum number of items to return
    :param sort_by: Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    result = AffectedItemsWazuhResult(none_msg='No user was shown',
                                      some_msg='Some users could not be shown',
                                      all_msg='All specified users were shown')
    affected_items = list()
    with AuthenticationManager() as auth:
        for username in username_list:
            user = auth.get_user(username)
            affected_items.append(user) if user else result.add_failed_item(id_=username, error=WazuhError(5001))

    processed_items = process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields,
                                    complementary_search=complementary_search, sort_by=sort_by,
                                    sort_ascending=sort_ascending, offset=offset, limit=limit)
    result.affected_items = processed_items['items']
    result.total_affected_items = processed_items['totalItems']

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


@expose_resources(actions=['security:update'], resources=['user:id:{username}'])
def update_user(username=None, password=None):
    """Update a specified user

    :param username: Name for the new user
    :param password: Password for the new user
    :return: Status message
    """
    if not _user_password.match(password):
        raise WazuhError(5007)
    result = AffectedItemsWazuhResult(all_msg='User modified correctly',
                                      none_msg='User could not be updated')
    with AuthenticationManager() as auth:
        query = auth.update_user(username[0], password)
        if query is False:
            result.add_failed_item(id_=username[0], error=WazuhError(5001))
        else:
            result.affected_items.append(auth.get_user(username[0]))
            result.total_affected_items += 1

    return result


@expose_resources(actions=['security:delete'], resources=['user:id:{username_list}'],
                  post_proc_kwargs={'exclude_codes': [5001, 5004]})
def delete_user(username_list):
    """Delete a specified user

    :param username_list: List of usernames
    :return: Status message
    """
    result = AffectedItemsWazuhResult(none_msg='No user was deleted',
                                      some_msg='Some users could not be deleted',
                                      all_msg='Users deleted correctly')
    with AuthenticationManager() as auth:
        for username in username_list:
            user = auth.get_user(username)
            query = auth.delete_user(username)
            if query is False:
                result.add_failed_item(id_=username, error=WazuhError(5001))
            elif query == 'admin':
                result.add_failed_item(id_=username, error=WazuhError(5004))
            elif user:
                result.affected_items.append(user)
                result.total_affected_items += 1

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
    with orm.RolesManager() as rm:
        for r_id in role_ids:
            role = rm.get_role_id(int(r_id))
            if role != SecurityError.ROLE_NOT_EXIST:
                affected_items.append(role.to_dict())
            else:
                # Role id does not exist
                result.add_failed_item(id_=r_id, error=WazuhError(4002))

    affected_items = process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields,
                                   complementary_search=complementary_search, sort_by=sort_by,
                                   sort_ascending=sort_ascending, offset=offset, limit=limit)['items']
    result.affected_items = affected_items
    result.total_affected_items = len(affected_items)

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
    with orm.RolesManager() as rm:
        for r_id in role_ids:
            role = rm.get_role_id(int(r_id))
            role_delete = rm.delete_role(int(r_id))
            if role_delete == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=r_id, error=WazuhError(4008))
            elif role_delete is False:
                result.add_failed_item(id_=r_id, error=WazuhError(4002))
            elif role:
                result.affected_items.append(role.to_dict())
                result.total_affected_items += 1

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
    with orm.RolesManager() as rm:
        status = rm.add_role(name=name, rule=rule)
        if status == SecurityError.ALREADY_EXIST:
            result.add_failed_item(id_=name, error=WazuhError(4005))
        elif status == SecurityError.INVALID:
            result.add_failed_item(id_=name, error=WazuhError(4003))
        else:
            result.affected_items.append(rm.get_role(name=name).to_dict())
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
    with orm.RolesManager() as rm:
        status = rm.update_role(role_id=int(role_id[0]), name=name, rule=rule)
        if status == SecurityError.ALREADY_EXIST:
            result.add_failed_item(id_=int(role_id[0]), error=WazuhError(4005))
        elif status == SecurityError.INVALID:
            result.add_failed_item(id_=int(role_id[0]), error=WazuhError(4003))
        elif status == SecurityError.ROLE_NOT_EXIST:
            result.add_failed_item(id_=int(role_id[0]), error=WazuhError(4002))
        elif status == SecurityError.ADMIN_RESOURCES:
            result.add_failed_item(id_=int(role_id[0]), error=WazuhError(4008))
        else:
            result.affected_items.append(rm.get_role_id(role_id=role_id[0]).to_dict())
            result.total_affected_items += 1

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
    with orm.PoliciesManager() as pm:
        for p_id in policy_ids:
            policy = pm.get_policy_id(int(p_id))
            if policy != SecurityError.POLICY_NOT_EXIST:
                affected_items.append(policy.to_dict())
            else:
                # Policy id does not exist
                result.add_failed_item(id_=p_id, error=WazuhError(4007))

    affected_items = process_array(affected_items, search_text=search_text, search_in_fields=search_in_fields,
                                   complementary_search=complementary_search, sort_by=sort_by,
                                   sort_ascending=sort_ascending, offset=offset, limit=limit)['items']
    result.affected_items = affected_items
    result.total_affected_items = len(affected_items)

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
    with orm.PoliciesManager() as pm:
        for p_id in policy_ids:
            policy = pm.get_policy_id(int(p_id))
            policy_delete = pm.delete_policy(int(p_id))
            if policy_delete == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=p_id, error=WazuhError(4008))
            elif policy_delete is False:
                result.add_failed_item(id_=p_id, error=WazuhError(4007))
            elif policy:
                result.affected_items.append(policy.to_dict())
                result.total_affected_items += 1

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
    with orm.PoliciesManager() as pm:
        status = pm.add_policy(name=name, policy=policy)
        if status == SecurityError.ALREADY_EXIST:
            result.add_failed_item(id_=name, error=WazuhError(4009))
        elif status == SecurityError.INVALID:
            result.add_failed_item(id_=name, error=WazuhError(4006))
        else:
            result.affected_items.append(pm.get_policy(name=name).to_dict())
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
    with orm.PoliciesManager() as pm:
        status = pm.update_policy(policy_id=int(policy_id[0]), name=name, policy=policy)
        if status == SecurityError.ALREADY_EXIST:
            result.add_failed_item(id_=int(policy_id[0]), error=WazuhError(4013))
        elif status == SecurityError.INVALID:
            result.add_failed_item(id_=int(policy_id[0]), error=WazuhError(4006))
        elif status == SecurityError.POLICY_NOT_EXIST:
            result.add_failed_item(id_=int(policy_id[0]), error=WazuhError(4007))
        elif status == SecurityError.ADMIN_RESOURCES:
            result.add_failed_item(id_=int(policy_id[0]), error=WazuhError(4008))
        else:
            result.affected_items.append(pm.get_policy_id(policy_id[0]).to_dict())
            result.total_affected_items += 1

    return result


@expose_resources(actions=['security:update'], resources=['role:id:{role_id}', 'policy:id:{policy_ids}'],
                  post_proc_kwargs={'exclude_codes': [4002, 4007, 4008, 4011]})
def set_role_policy(role_id, policy_ids):
    """Create a relationship between a role and a policy

    :param role_id: The new role_id
    :param policy_ids: List of policies ids
    :return Role-Policies information
    """
    result = AffectedItemsWazuhResult(none_msg=f'No link created to role {role_id[0]}',
                                      some_msg=f'Some policies could not be linked to role {role_id[0]}',
                                      all_msg=f'All policies were linked to role {role_id[0]}')
    with orm.RolesPoliciesManager() as rpm:
        for policy_id in policy_ids:
            role_policy = rpm.add_policy_to_role(role_id=role_id[0], policy_id=policy_id)
            if role_policy == SecurityError.ALREADY_EXIST:
                result.add_failed_item(id_=policy_id, error=WazuhError(4011))
            elif role_policy == SecurityError.ROLE_NOT_EXIST:
                result.add_failed_item(id_=policy_id, error=WazuhError(4002))
            elif role_policy == SecurityError.POLICY_NOT_EXIST:
                result.add_failed_item(id_=policy_id, error=WazuhError(4007))
            elif role_policy == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=policy_id, error=WazuhError(4008))
            else:
                result.affected_items.append(policy_id)
                result.total_affected_items += 1

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
    with orm.RolesPoliciesManager() as rpm:
        for policy_id in policy_ids:
            role_policy = rpm.remove_policy_in_role(role_id=role_id[0], policy_id=policy_id)
            if role_policy == SecurityError.INVALID:
                result.add_failed_item(id_=policy_id, error=WazuhError(4010))
            elif role_policy == SecurityError.ROLE_NOT_EXIST:
                result.add_failed_item(id_=policy_id, error=WazuhError(4002))
            elif role_policy == SecurityError.POLICY_NOT_EXIST:
                result.add_failed_item(id_=policy_id, error=WazuhError(4007))
            elif role_policy == SecurityError.ADMIN_RESOURCES:
                result.add_failed_item(id_=policy_id, error=WazuhError(4008))
            else:
                result.affected_items.append(policy_id)
                result.total_affected_items += 1

    return result


@expose_resources(actions=['security:revoke'], resources=['*:*:*'])
def revoke_tokens():
    """ Revoke all tokens """
    validation.key = int(time())

    return WazuhResult({'msg': 'Tokens revoked succesfully'})
