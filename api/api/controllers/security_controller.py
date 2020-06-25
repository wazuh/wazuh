# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import re
from json import JSONDecodeError

from aiohttp import web

from api.api_exception import APIError
from api.authentication import generate_token
from api.configuration import default_security_configuration
from api.encoder import dumps, prettify
from api.models.configuration_model import SecurityConfigurationModel
from api.models.security_model import CreateUserModel, UpdateUserModel
from api.models.token_response import TokenResponse
from api.util import remove_nones_to_dict, raise_if_exc, parse_api_param
from wazuh import security
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.exception import WazuhError
from wazuh.rbac import preprocessor
from wazuh.results import AffectedItemsWazuhResult

logger = logging.getLogger('wazuh')
auth_re = re.compile(r'basic (.*)', re.IGNORECASE)


async def login_user(request, user: str, auth_context=None):
    """User/password authentication to get an access token.
    This method should be called to get an API token. This token will expire at some time. # noqa: E501

    Parameters
    ----------
    request : connexion.request
    user : str
        Name of the user who wants to be authenticated
    auth_context : dict, optional
        User's authorization context

    Returns
    -------
    TokenResponse
    """
    f_kwargs = {'auth_context': auth_context,
                'user_id': user}

    dapi = DistributedAPI(f=preprocessor.get_permissions,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=TokenResponse(token=generate_token(user_id=user, rbac_policies=data.dikt)),
                             status=200, dumps=dumps)


async def get_users(request, usernames: list = None, pretty=False, wait_for_complete=False,
                    offset=0, limit=None, search=None, sort=None):
    """Returns information from all system roles.

    Parameters
    ----------
    request : connexion.request
    usernames : list, optional
        List of users to be obtained
    pretty : bool, optional
        Show results in human-readable format
    wait_for_complete : bool, optional
        Disable timeout response
    offset : int, optional
        First item to return
    limit : int, optional
        Maximum number of items to return
    search : str
        Looks for elements with the specified string
    sort : str, optional
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order

    Returns
    -------
    Roles information
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

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def create_user(request):
    """Create a new user.

    Parameters
    ----------
    request : connexion.request

    Returns
    -------
    User data
    """
    f_kwargs = await CreateUserModel.get_kwargs(request)
    dapi = DistributedAPI(f=security.create_user,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def update_user(request, username: str):
    """Modify an existent user.

    Parameters
    ----------
    request : connexion.request
    username : str
        Username of the user to be updated

    Returns
    -------
    User data
    """
    f_kwargs = await UpdateUserModel.get_kwargs(request, additional_kwargs={'username': username})
    dapi = DistributedAPI(f=security.update_user,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def delete_users(request, usernames: list = None):
    """Delete an existent list of users.

    Parameters
    ----------
    request : connexion.request
    usernames : list, optional
        Names of the users to be removed

    Returns
    -------
    Result of the operation
    """
    f_kwargs = {'username_list': usernames}
    dapi = DistributedAPI(f=security.remove_users,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger,
                          current_user=request['token_info']['sub'],
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=dumps)


async def get_roles(request, role_ids: list = None, pretty: bool = False, wait_for_complete: bool = False,
                    offset: int = 0, limit: int = None, search: str = None, sort: str = None):
    """

    Parameters
    ----------
    request : connexion.request
    role_ids : list, optional
        List of roles ids to be obtained
    pretty : bool, optional
        Show results in human-readable format
    wait_for_complete : bool, optional
        Disable timeout response
    offset : int, optional
        First item to return
    limit : int, optional
        Maximum number of items to return
    search : str, optional
        Looks for elements with the specified string
    sort : str, optional
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order

    Returns
    -------
    Roles information
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
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def add_role(request, pretty: bool = False, wait_for_complete: bool = False):
    """Add one specified role.

    Parameters
    ----------
    request : request.connexion
    pretty : bool, optional
        Show results in human-readable format
    wait_for_complete : bool, optional
        Disable timeout response

    Returns
    -------
    Role information
    """
    # get body parameters
    role_added_model = dict()
    try:
        role_added_model = await request.json()
    except JSONDecodeError as e:
        raise_if_exc(APIError(code=2005, details=e.msg))

    f_kwargs = {'name': role_added_model['name'], 'rule': role_added_model['rule']}

    dapi = DistributedAPI(f=security.add_role,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def remove_roles(request, role_ids: list = None, pretty: bool = False, wait_for_complete: bool = False):
    """Removes a list of roles in the system.

    Parameters
    ----------
    request : connexion.request
    role_ids : list, optional
        List of roles ids to be deleted
    pretty : bool, optional
        Show results in human-readable format
    wait_for_complete : bool, optional
        Disable timeout response

    Returns
    -------
    Two list with deleted roles and not deleted roles
    """
    f_kwargs = {'role_ids': role_ids}

    dapi = DistributedAPI(f=security.remove_roles,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def update_role(request, role_id: int, pretty: bool = False, wait_for_complete: bool = False):
    """Update the information of one specified role.

    Parameters
    ----------
    request : connexion.request
    role_id : int
        Specific role id in the system to be updated
    pretty : bool, optional
        Show results in human-readable format
    wait_for_complete : bool, optional
        Disable timeout response

    Returns
    -------
    Role information updated
    """
    # get body parameters
    role_added_model = dict()
    try:
        role_added_model = await request.json()
    except JSONDecodeError as e:
        raise_if_exc(APIError(code=2005, details=e.msg))

    f_kwargs = {'role_id': role_id, 'name': role_added_model.get('name', None),
                'rule': role_added_model.get('rule', None)}

    dapi = DistributedAPI(f=security.update_role,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_policies(request, policy_ids: list = None, pretty: bool = False, wait_for_complete: bool = False,
                       offset: int = 0, limit: int = None, search: str = None, sort: str = None):
    """Returns information from all system policies.

    Parameters
    ----------
    request : connexion.request
    policy_ids : list, optional
        List of policies
    pretty : bool, optional
        Show results in human-readable format
    wait_for_complete : bool, optional
        Disable timeout response
    offset : int, optional
        First item to return
    limit : int, optional
        Maximum number of items to return
    search : str, optional
        Looks for elements with the specified string
    sort : str, optional
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order

    Returns
    -------
    Policies information
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
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def add_policy(request, pretty: bool = False, wait_for_complete: bool = False):
    """Add one specified policy.

    Parameters
    ----------
    request : connexion.request
    pretty : bool, optional
        Show results in human-readable format
    wait_for_complete : bool, optional
        Disable timeout response

    Returns
    -------
    Policy information
    """
    # get body parameters
    policy_added_model = dict()
    try:
        policy_added_model = await request.json()
    except JSONDecodeError as e:
        raise_if_exc(APIError(code=2005, details=e.msg))

    f_kwargs = {'name': policy_added_model['name'], 'policy': policy_added_model['policy']}

    dapi = DistributedAPI(f=security.add_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def remove_policies(request, policy_ids: list = None, pretty: bool = False, wait_for_complete: bool = False):
    """Removes a list of roles in the system.

    Parameters
    ----------
    request : connexion.request
    policy_ids : list, optional
        List of policies ids to be deleted
    pretty : bool, optional
        Show results in human-readable format
    wait_for_complete : bool, optional
        Disable timeout response

    Returns
    -------
    Two list with deleted roles and not deleted roles
    """
    f_kwargs = {'policy_ids': policy_ids}

    dapi = DistributedAPI(f=security.remove_policies,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def update_policy(request, policy_id: int, pretty: bool = False, wait_for_complete: bool = False):
    """Update the information of one specified policy.

    Parameters
    ----------
    request : connexion.request
    policy_id : int
        Specific policy id in the system to be updated
    pretty : bool, optional
        Show results in human-readable format
    wait_for_complete : bool, optional
        Disable timeout response

    Returns
    -------
    Policy information updated
    """
    # get body parameters
    policy_added_model = dict()
    try:
        policy_added_model = await request.json()
    except JSONDecodeError as e:
        raise_if_exc(APIError(code=2005, details=e.msg))

    f_kwargs = {'policy_id': policy_id,
                'name': policy_added_model.get('name', None),
                'policy': policy_added_model.get('policy', None)}

    dapi = DistributedAPI(f=security.update_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def set_user_role(request, username: str, role_ids: list, position: int = None,
                        pretty: bool = False, wait_for_complete: bool = False):
    """Add a list of roles to one specified user.

    Parameters
    ----------
    request : connexion.request
    username : str
        User's username
    role_ids : list of int
        List of role ids
    position : int, optional
        Position where the new role will be inserted
    pretty : bool, optional
        Show results in human-readable format
    wait_for_complete : bool, optional
        Disable timeout response

    Returns
    -------
    Dict
        User-Role information
    """
    f_kwargs = {'user_id': username, 'role_ids': role_ids, 'position': position}
    dapi = DistributedAPI(f=security.set_user_role,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def remove_user_role(request, username: str, role_ids: list, pretty: bool = False,
                           wait_for_complete: bool = False):
    """Delete a list of roles of one specified user.

    Parameters
    ----------
    request : connexion.request
    username : str
    role_ids : list
        List of roles ids
    pretty : bool, optional
        Show results in human-readable format
    wait_for_complete: bool, optional
        Disable timeout response

    Returns
    -------
    Result of the operation
    """
    f_kwargs = {'user_id': username, 'role_ids': role_ids}

    dapi = DistributedAPI(f=security.remove_user_role,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def set_role_policy(request, role_id, policy_ids, position=None, pretty=False, wait_for_complete=False):
    """Add a list of policies to one specified role.

    Parameters
    ----------
    role_id : int
        Role ID
    policy_ids : list of int
        List of policy IDs
    position : int
        Position where the new role will be inserted
    pretty : bool
        Show results in human-readable format
    wait_for_complete : bool
        Disable timeout response

    Returns
    -------
    dict
        Role information
    """
    f_kwargs = {'role_id': role_id, 'policy_ids': policy_ids, 'position': position}

    dapi = DistributedAPI(f=security.set_role_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def remove_role_policy(request, role_id: int, policy_ids: list, pretty: bool = False,
                             wait_for_complete: bool = False):
    """Delete a list of policies of one specified role.

    Parameters
    ----------
    request : request.connexion
    role_id : int
    policy_ids : list
        List of policy ids
    pretty : bool, optional
        Show results in human-readable format
    wait_for_complete : bool, optional
        Disable timeout response

    Returns
    -------
    Role information
    """
    f_kwargs = {'role_id': role_id, 'policy_ids': policy_ids}

    dapi = DistributedAPI(f=security.remove_role_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_rbac_resources(pretty: bool = False, resource: str = None):
    """Gets all the current defined resources for RBAC.

    Parameters
    ----------
    pretty : bool, optional
        Show results in human-readable format
    resource : str, optional
        Show the information of the specified resource. Ex: agent:id

    Returns
    -------
    dict
        RBAC resources
    """
    f_kwargs = {'resource': resource}

    dapi = DistributedAPI(f=security.get_rbac_resources,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=True,
                          logger=logger
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_rbac_actions(pretty: bool = False, endpoint: str = None):
    """Gets all the current defined actions for RBAC.

    Parameters
    ----------
    pretty : bool, optional
        Show results in human-readable format
    endpoint : str, optional
        Show actions and resources for the specified endpoint. Ex: GET /agents

    Returns
    -------
    dict
        RBAC actions
    """
    f_kwargs = {'endpoint': endpoint}

    dapi = DistributedAPI(f=security.get_rbac_actions,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=True,
                          logger=logger
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def revoke_all_tokens(request):
    """Revoke all tokens."""
    f_kwargs = {}

    dapi = DistributedAPI(f=security.revoke_tokens,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          broadcasting=True,
                          wait_for_complete=True,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())
    status = 200
    if type(data) == AffectedItemsWazuhResult and len(data.affected_items) == 0:
        raise_if_exc(WazuhError(4000, data.message))

    return web.json_response(data=data, status=status, dumps=dumps)


async def get_security_config(request, pretty=False, wait_for_complete=False):
    """Get active security configuration.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response

    Returns
    -------
    dict
        Security configuration
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=security.get_security_config,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def put_security_config(request, pretty=False, wait_for_complete=False):
    """Update current security configuration with the given one.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {'updated_config': await SecurityConfigurationModel.get_kwargs(request)}

    dapi = DistributedAPI(f=security.update_security_config,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def delete_security_config(request, pretty=False, wait_for_complete=False):
    """Restore default security configuration.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    """
    f_kwargs = {"updated_config": await SecurityConfigurationModel.get_kwargs(default_security_configuration)}

    dapi = DistributedAPI(f=security.update_security_config,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
