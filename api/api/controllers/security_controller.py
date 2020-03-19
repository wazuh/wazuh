# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import re

from aiohttp import web

from api.authentication import generate_token
from api.encoder import dumps
from api.models.token_response import TokenResponse
from api.util import remove_nones_to_dict, raise_if_exc, parse_api_param
from wazuh import security
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.exception import WazuhError
from wazuh.rbac.orm import AuthenticationManager

logger = logging.getLogger('wazuh')
auth_re = re.compile(r'basic (.*)', re.IGNORECASE)


async def login_user(request, user, auth_context=None):
    """User/password authentication to get an access token

    This method should be called to get an API token. This token will expire at some time. # noqa: E501
    :return: TokenResponse
    """
    with AuthenticationManager() as auth:
        if auth.user_auth_context(user):
            return web.json_response(data=TokenResponse(token=generate_token(user_id=user, auth_context=auth_context)),
                                     status=200, dumps=dumps)
    return web.json_response(data=TokenResponse(token=generate_token(user_id=user)),
                             status=200, dumps=dumps)


async def get_users(request, usernames: list = None, pretty=False, wait_for_complete=False,
                    offset=0, limit=None, search=None, sort=None):
    """Returns information from all system roles

    :param usernames: List of users to be obtained
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :return Roles information
    """
    f_kwargs = {'username_list': usernames, 'offset': offset, 'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['username'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None}
    dapi = DistributedAPI(f=security.get_users,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


def _check_body(f_kwargs, keys: list = None):
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


async def create_user(request):
    """Create a new user

    :return: User data
    """
    f_kwargs = {**await request.json()}
    validate = _check_body(f_kwargs)
    if validate is not True:
        raise WazuhError(5005, extra_message='Invalid field found {}'.format(validate))
    dapi = DistributedAPI(f=security.create_user,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def update_user(request, username):
    """Modify an existent user

    :param username: Name of the user to be modified
    :return: User data
    """
    f_kwargs = {'username': username, **await request.json()}
    validate = _check_body(f_kwargs)
    if validate is not True:
        raise WazuhError(5005, extra_message='Invalid field found {}'.format(validate))
    dapi = DistributedAPI(f=security.update_user,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def delete_users(request, usernames=None):
    """Delete an existent list of users

    :param usernames: Names of the users to be removed
    :return: Result of the operation
    """
    f_kwargs = {'username_list': usernames}
    dapi = DistributedAPI(f=security.remove_users,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def get_roles(request, role_ids=None, pretty=False, wait_for_complete=False, offset=0, limit=None, search=None,
                    sort=None):
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
    f_kwargs = {'role_ids': role_ids, 'offset': offset, 'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['id'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None
                }

    dapi = DistributedAPI(f=security.get_roles,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def add_role(request, pretty=False, wait_for_complete=False):
    """Add one specified role

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Role information
    """
    # get body parameters
    role_added_model = await request.json()

    f_kwargs = {'name': role_added_model['name'], 'rule': role_added_model['rule']}

    dapi = DistributedAPI(f=security.add_role,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def remove_roles(request, role_ids=None, pretty=False, wait_for_complete=False):
    """Removes a list of roles in the system

    :param role_ids: List of roles ids to be deleted
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Two list with deleted roles and not deleted roles
    """
    f_kwargs = {'role_ids': role_ids}

    dapi = DistributedAPI(f=security.remove_roles,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def update_role(request, role_id, pretty=False, wait_for_complete=False):
    """Update the information of one specified role

    :param role_id: Specific role id in the system to be updated
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Role information updated
    """
    # get body parameters
    role_added_model = await request.json()

    f_kwargs = {'role_id': role_id, 'name': role_added_model.get('name', None),
                'rule': role_added_model.get('rule', None)}

    dapi = DistributedAPI(f=security.update_role,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def get_policies(request, policy_ids=None, pretty=False, wait_for_complete=False, offset=0, limit=None,
                       search=None, sort=None):
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
    f_kwargs = {'policy_ids': policy_ids, 'offset': offset, 'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['id'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None
                }

    dapi = DistributedAPI(f=security.get_policies,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def add_policy(request, pretty=False, wait_for_complete=False):
    """Add one specified policy

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Policy information
    """
    # get body parameters
    policy_added_model = await request.json()

    f_kwargs = {'name': policy_added_model['name'], 'policy': policy_added_model['policy']}

    dapi = DistributedAPI(f=security.add_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def remove_policies(request, policy_ids=None, pretty=False, wait_for_complete=False):
    """Removes a list of roles in the system

    :param policy_ids: List of policies ids to be deleted
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Two list with deleted roles and not deleted roles
    """
    f_kwargs = {'policy_ids': policy_ids}

    dapi = DistributedAPI(f=security.remove_policies,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def update_policy(request, policy_id, pretty=False, wait_for_complete=False):
    """Update the information of one specified policy

    :param policy_id: Specific policy id in the system to be updated
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Policy information updated
    """
    # get body parameters
    policy_added_model = await request.json()

    f_kwargs = {'policy_id': policy_id,
                'name': policy_added_model.get('name', None),
                'policy': policy_added_model.get('policy', None)}

    dapi = DistributedAPI(f=security.update_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def set_user_role(request, username, role_ids, pretty=False, wait_for_complete=False):
    """Add a list of roles to one specified user

    :param username: User's username
    :param role_ids: List of role ids
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return User-Role information
    """
    f_kwargs = {'user_id': username, 'role_ids': role_ids}

    dapi = DistributedAPI(f=security.set_user_role,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def remove_user_role(request, username, role_ids, pretty=False, wait_for_complete=False):
    """Delete a list of roles of one specified user

    :param username: User's username
    :param role_ids: List of roles ids
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Result of the operation
    """
    f_kwargs = {'user_id': username, 'role_ids': role_ids}

    dapi = DistributedAPI(f=security.remove_user_role,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def set_role_policy(request, role_id, policy_ids, pretty=False, wait_for_complete=False):
    """Add a list of policies to one specified role

    :param role_id: Role id
    :param policy_ids: List of policy ids
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Role information
    """
    f_kwargs = {'role_id': role_id, 'policy_ids': policy_ids}

    dapi = DistributedAPI(f=security.set_role_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def remove_role_policy(request, role_id, policy_ids, pretty=False, wait_for_complete=False):
    """Delete a list of policies of one specified role

    :param role_id: Role id
    :param policy_ids: List of policy ids
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Role information
    """
    f_kwargs = {'role_id': role_id, 'policy_ids': policy_ids}

    dapi = DistributedAPI(f=security.remove_role_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def revoke_all_tokens(request):
    """ Revoke all tokens """

    f_kwargs = {}

    dapi = DistributedAPI(f=security.revoke_tokens,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)
