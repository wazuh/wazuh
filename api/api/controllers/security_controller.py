# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging
import re

import connexion

from api.authentication import generate_token
from api.authentication import get_permissions
from api.models.base_model_ import Data
from api.models.token_response import TokenResponse
from api.util import remove_nones_to_dict, exception_handler, raise_if_exc, parse_api_param
from wazuh import security
from wazuh.cluster.dapi.dapi import DistributedAPI
from wazuh.exception import WazuhError

loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')
auth_re = re.compile(r'basic (.*)', re.IGNORECASE)


@exception_handler
def login_user(user):
    """User/password authentication to get an access token

    This method should be called to get an API token. This token will expire at some time. # noqa: E501
    :return: TokenResponse
    """

    return TokenResponse(token=generate_token(user)), 200


@exception_handler
def get_users(username: list = None):
    """Get username of a specified user

    :return: All users data
    """
    func = security.get_users_all if username is None else security.get_users
    rbac = get_permissions(connexion.request.headers['Authorization'])
    f_kwargs = {'username_list': username, 'rbac': rbac}
    dapi = DistributedAPI(f=func,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def check_body(f_kwargs, keys: list = None):
    """Checks that body is correct

    :param f_kwargs: Body to be checked
    :param keys: Keys that the body must have only and exclusively
    :return: 0 -> Correct | str -> Incorrect
    """
    if keys is None:
        keys = ['username', 'password']
    for key in f_kwargs.keys():
        if key not in keys:
            return False

    return True


@exception_handler
def create_user():
    """Create a new user

    :return: User data
    """
    f_kwargs = {**connexion.request.get_json()}
    validate = check_body(f_kwargs)
    if validate is not True:
        raise WazuhError(5005, extra_message='Invalid field found {}'.format(validate))
    dapi = DistributedAPI(f=security.create_user,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def update_user(username):
    """Modify an existent user

    :param username: Name of the user to be modified
    :return: User data
    """
    f_kwargs = {'username': username, **connexion.request.get_json()}
    validate = check_body(f_kwargs)
    if validate is not True:
        raise WazuhError(5005, extra_message='Invalid field found {}'.format(validate))
    rbac = get_permissions(connexion.request.headers['Authorization'])
    f_kwargs['rbac'] = rbac
    dapi = DistributedAPI(f=security.update_user,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def delete_users(username=None):
    """Delete an existent user

    :param username: Name of the user to be removed
    :return: Result of the operation
    """
    rbac = get_permissions(connexion.request.headers['Authorization'])
    f_kwargs = {'username': username, 'rbac': rbac}
    dapi = DistributedAPI(f=security.delete_user,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_roles(role_ids=None, pretty=False, wait_for_complete=False, offset=0, limit=None, search=None, sort=None):
    """Returns information from all system roles

    :param role_ids: List of roles ids to be obtained
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :return Roles information
    """
    func = security.get_roles if role_ids is None else security.get_role
    rbac = get_permissions(connexion.request.headers['Authorization'])
    f_kwargs = {'role_ids': role_ids, 'rbac': rbac, 'offset': offset, 'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['id'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None
                }

    dapi = DistributedAPI(f=func,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def add_role(pretty=False, wait_for_complete=False):
    """Add one specified role

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Role information
    """
    # get body parameters
    if connexion.request.is_json:
        # role_added_model = RoleAdded.from_dict(connexion.request.get_json())
        role_added_model = connexion.request.get_json()
    else:
        raise WazuhError(1749, extra_remediation='[official documentation]'
                                                 '(TO BE DEFINED) '
                                                 'to get more information about API call')

    # f_kwargs = {'role_id': role_id, **{}, **role_added_model.to_dict()}
    f_kwargs = role_added_model

    dapi = DistributedAPI(f=security.add_role,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def remove_roles(role_ids=None, pretty=False, wait_for_complete=False):
    """Removes a list of roles in the system

    :param role_ids: List of roles ids to be deleted
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Two list with deleted roles and not deleted roles
    """
    func = security.remove_roles if role_ids is None else security.remove_role
    rbac = get_permissions(connexion.request.headers['Authorization'])
    f_kwargs = {'rbac': rbac, 'role_ids': role_ids}

    dapi = DistributedAPI(f=func,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def update_role(role_id, pretty=False, wait_for_complete=False):
    """Update the information of one specified role

    :param role_id: Specific role id in the system to be updated
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Role information updated
    """
    # get body parameters
    if connexion.request.is_json:
        # role_added_model = RoleAdded.from_dict(connexion.request.get_json())
        role_added_model = connexion.request.get_json()
    else:
        raise WazuhError(1749, extra_remediation='[official documentation]'
                                                 '(TO BE DEFINED) '
                                                 'to get more information about API call')

    rbac = get_permissions(connexion.request.headers['Authorization'])
    f_kwargs = {'rbac': rbac, 'role_id': role_id, 'name': role_added_model['name'], 'rule': role_added_model['rule']}

    dapi = DistributedAPI(f=security.update_role,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_policies(policy_ids=None, pretty=False, wait_for_complete=False, offset=0, limit=None, search=None, sort=None):
    """Returns information from all system policies

    :param policy_ids: List of policies
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :return Policies information
    """
    func = security.get_policies if policy_ids is None else security.get_policy
    rbac = get_permissions(connexion.request.headers['Authorization'])
    f_kwargs = {'policy_ids': policy_ids, 'rbac': rbac, 'offset': offset, 'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['id'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None
                }

    dapi = DistributedAPI(f=func,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def add_policy(pretty=False, wait_for_complete=False):
    """Add one specified policy

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Policy information
    """
    # get body parameters
    if connexion.request.is_json:
        policy_added_model = connexion.request.get_json()
    else:
        raise WazuhError(1749, extra_remediation='[official documentation]'
                                                 '(TO BE DEFINED) '
                                                 'to get more information about API call')

    f_kwargs = policy_added_model

    dapi = DistributedAPI(f=security.add_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def remove_policies(policy_ids=None, pretty=False, wait_for_complete=False):
    """Removes a list of roles in the system

    :param policy_ids: List of policies ids to be deleted
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Two list with deleted roles and not deleted roles
    """
    func = security.remove_policies if policy_ids is None else security.remove_policy
    rbac = get_permissions(connexion.request.headers['Authorization'])
    f_kwargs = {'rbac': rbac, 'policy_ids': policy_ids}

    dapi = DistributedAPI(f=func,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def update_policy(policy_id, pretty=False, wait_for_complete=False):
    """Update the information of one specified policy

    :param policy_id: Specific policy id in the system to be updated
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Policy information updated
    """
    # get body parameters
    if connexion.request.is_json:
        policy_added_model = connexion.request.get_json()
    else:
        raise WazuhError(1749, extra_remediation='[official documentation]'
                                                 '(TO BE DEFINED) '
                                                 'to get more information about API call')

    rbac = get_permissions(connexion.request.headers['Authorization'])
    f_kwargs = {'rbac': rbac, 'policy_id': policy_id,
                'name': policy_added_model['name'],
                'policy': policy_added_model['policy']}

    dapi = DistributedAPI(f=security.update_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def set_role_policy(role_id, policy_ids, pretty=False, wait_for_complete=False):
    """Add a list of policies to one specified role

    :param role_id: Role id
    :param policy_ids: List of policies ids
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Role information
    """
    rbac = get_permissions(connexion.request.headers['Authorization'])
    f_kwargs = {'rbac': rbac, 'role_id': role_id, 'policy_ids': policy_ids}

    dapi = DistributedAPI(f=security.set_role_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def remove_role_policy(role_id, policy_ids, pretty=False, wait_for_complete=False):
    """Delete a list of policies of one specified role

    :param role_id: Role id
    :param policy_ids: List of policies ids
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Role information
    """
    rbac = get_permissions(connexion.request.headers['Authorization'])
    f_kwargs = {'rbac': rbac, 'role_id': role_id, 'policy_ids': policy_ids}

    dapi = DistributedAPI(f=security.remove_role_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200
