# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
import re

from connexion import request
from connexion.lifecycle import ConnexionResponse

from api.encoder import dumps
from api.models.security_token_response_model import TokenResponseModel
from api.authentication import generate_token
from api.configuration import default_security_configuration
from api.controllers.util import json_response, JSON_CONTENT_TYPE
from api.models.base_model_ import Body
from api.models.configuration_model import SecurityConfigurationModel
from api.models.security_model import (CreateUserModel, PolicyModel, RoleModel,
                                       RuleModel, UpdateUserModel)
from api.util import (deprecate_endpoint, parse_api_param, raise_if_exc,
                      remove_nones_to_dict)
from wazuh import security, __version__
from wazuh.core.cluster.control import get_system_nodes
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.exception import WazuhException, WazuhPermissionError
from wazuh.core.results import AffectedItemsWazuhResult, WazuhResult
from wazuh.core.security import revoke_tokens
from wazuh.rbac import preprocessor

logger = logging.getLogger('wazuh-api')
auth_re = re.compile(r'basic (.*)', re.IGNORECASE)


@deprecate_endpoint(link=f'https://documentation.wazuh.com/{__version__}/user-manual/api/reference.html#'
                         f'operation/api.controllers.security_controller.login_user')
async def deprecated_login_user(user: str, raw: bool = False) -> ConnexionResponse:
    """User/password authentication to get an access token.
    This method should be called to get an API token. This token will expire at some time.

    Parameters
    ----------
    user : str
        Name of the user who wants to be authenticated.
    raw : bool, optional
        Respond in raw format. Default `False`

    Returns
    -------
    ConnexionResponse
        Raw or JSON response with the generated access token.
    """
    f_kwargs = {'user_id': user}

    dapi = DistributedAPI(f=preprocessor.get_permissions,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger
                          )
    data = raise_if_exc(await dapi.distribute_function())

    token = None
    try:
        token = generate_token(user_id=user, data=data.dikt)
    except WazuhException as e:
        raise_if_exc(e)

    return ConnexionResponse(body=token,
                             content_type='text/plain',
                             status_code=200) if raw else \
           ConnexionResponse(body=dumps(WazuhResult({'data': TokenResponseModel(token=token)})),
                             content_type=JSON_CONTENT_TYPE,
                             status_code=200)


async def login_user(user: str, raw: bool = False) -> ConnexionResponse:
    """User/password authentication to get an access token.
    This method should be called to get an API token. This token will expire at some time.

    Parameters
    ----------
    user : str
        Name of the user who wants to be authenticated.
    raw : bool, optional
        Respond in raw format. Default `False`

    Returns
    -------
    ConnexionResponse
        Raw or JSON response with the generated access token.
    """
    f_kwargs = {'user_id': user}

    dapi = DistributedAPI(f=preprocessor.get_permissions,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger
                          )
    data = raise_if_exc(await dapi.distribute_function())

    token = None
    try:
        token = generate_token(user_id=user, data=data.dikt)
    except WazuhException as e:
        raise_if_exc(e)

    return ConnexionResponse(body=token,
                             content_type='text/plain',
                             status_code=200) if raw else \
           ConnexionResponse(body=dumps(WazuhResult({'data': TokenResponseModel(token=token)})),
                             content_type=JSON_CONTENT_TYPE,
                             status_code=200)


async def run_as_login(user: str, raw: bool = False) -> ConnexionResponse:
    """User/password authentication to get an access token.
    This method should be called to get an API token using an authorization context body. This token will expire at
    some time.

    Parameters
    ----------
    user : str
        Name of the user who wants to be authenticated.
    raw : bool, optional
        Respond in raw format. Default `False`

    Returns
    -------
    ConnexionResponse
        Raw or JSON response with the generated access token.
    """
    auth_context = await request.json()
    f_kwargs = {'user_id': user, 'auth_context': auth_context}

    dapi = DistributedAPI(f=preprocessor.get_permissions,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger
                          )
    data = raise_if_exc(await dapi.distribute_function())

    token = None
    try:
        token = generate_token(user_id=user, data=data.dikt, auth_context=auth_context)
    except WazuhException as e:
        raise_if_exc(e)

    return ConnexionResponse(body=token,
                             content_type='text/plain',
                             status_code=200) if raw else \
           ConnexionResponse(body=dumps(WazuhResult({'data': TokenResponseModel(token=token)})),
                             content_type=JSON_CONTENT_TYPE,
                             status_code=200)


async def get_user_me(pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Returns information about the current user.

    Parameters
    ----------
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response with the user information.
    """
    f_kwargs = {'token': request.context['token_info']}
    dapi = DistributedAPI(f=security.get_user_me,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger,
                          wait_for_complete=wait_for_complete,
                          current_user=request.context['token_info']['sub'],
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_user_me_policies(pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Return processed RBAC policies and rbac_mode for the current user.

    Parameters
    ----------
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response with the user RBAC policies and mode.
    """
    data = WazuhResult({'data': request.context['token_info']['rbac_policies'],
                        'message': "Current user processed policies information was returned"})

    return json_response(data, pretty=pretty)


async def logout_user(pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Invalidate all current user's tokens.

    Parameters
    ----------
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """

    dapi = DistributedAPI(f=security.revoke_current_user_tokens,
                          request_type='local_master',
                          is_async=False,
                          current_user=request.context['token_info']['sub'],
                          wait_for_complete=wait_for_complete,
                          logger=logger
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_users(user_ids: list = None, pretty: bool = False, wait_for_complete: bool = False,
                    offset: int = 0, limit: int = None, search: str = None, select: str = None,
                    sort: str = None, q: str = None, distinct: bool = False) -> ConnexionResponse:
    """Returns information from all system users.

    Parameters
    ----------
    user_ids : list, optional
        List of users to be obtained.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.
    offset : int, optional
        First item to return.
    limit : int, optional
        Maximum number of items to return.
    search : str
        Looks for elements with the specified string.
    select : str
        Select which fields to return (separated by comma).
    sort : str, optional
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    q : str
        Query to filter results by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response with the users information.
    """
    f_kwargs = {'user_ids': user_ids, 'offset': offset, 'limit': limit, 'select': select,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['id'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'q': q,
                'distinct': distinct}

    dapi = DistributedAPI(f=security.get_users,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger,
                          wait_for_complete=wait_for_complete,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def edit_run_as(user_id: str, allow_run_as: bool, pretty: bool = False,
                      wait_for_complete: bool = False) -> ConnexionResponse:
    """Modify the specified user's allow_run_as flag.

    Parameters
    ----------
    user_id : str
        User ID of the user to be updated.
    allow_run_as : bool
        Enable or disable authorization context login method for the specified user.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'user_id': user_id, 'allow_run_as': allow_run_as}

    dapi = DistributedAPI(f=security.edit_run_as,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger,
                          current_user=request.context['token_info']['sub'],
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          wait_for_complete=wait_for_complete
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def create_user(pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Create a new user.

    Parameters
    ----------
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    Body.validate_content_type(request, expected_content_type=JSON_CONTENT_TYPE)
    f_kwargs = await CreateUserModel.get_kwargs(request)

    dapi = DistributedAPI(f=security.create_user,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          wait_for_complete=wait_for_complete
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def update_user(user_id: str, pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Modify an existent user.

    Parameters
    ----------
    user_id : str
        User ID of the user to be updated.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    Body.validate_content_type(request, expected_content_type=JSON_CONTENT_TYPE)
    f_kwargs = await UpdateUserModel.get_kwargs(request,
                                                additional_kwargs=
                                                {'user_id': user_id,
                                                  'current_user': request.get("user")})

    dapi = DistributedAPI(f=security.update_user,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          wait_for_complete=wait_for_complete
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def delete_users(user_ids: list = None, pretty: bool = False,
                       wait_for_complete: bool = False) -> ConnexionResponse:
    """Delete an existent list of users.

    Parameters
    ----------
    user_ids : list, optional
        IDs of the users to be removed.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    if 'all' in user_ids:
        user_ids = None
    f_kwargs = {'user_ids': user_ids}

    dapi = DistributedAPI(f=security.remove_users,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          logger=logger,
                          current_user=request.context['token_info']['sub'],
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          wait_for_complete=wait_for_complete
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_roles(role_ids: list = None, pretty: bool = False, wait_for_complete: bool = False,
                    offset: int = 0, limit: int = None, search: str = None, select: str = None,
                    sort: str = None, q: str = None, distinct: bool = False) -> ConnexionResponse:
    """Get information about the security roles in the system.

    Parameters
    ----------
    role_ids : list, optional
        List of roles ids to be obtained.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.
    offset : int, optional
        First item to return.
    limit : int, optional
        Maximum number of items to return.
    search : str, optional
        Looks for elements with the specified string.
    select : str
        Select which fields to return (separated by comma).
    sort : str, optional
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    q : str
        Query to filter results by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response with the roles information.
    """
    f_kwargs = {'role_ids': role_ids, 'offset': offset, 'limit': limit, 'select': select,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['id'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'q': q,
                'distinct': distinct
                }

    dapi = DistributedAPI(f=security.get_roles,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def add_role(pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Add a specified role.

    Parameters
    ----------
    request : request.connexion
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    # Get body parameters
    Body.validate_content_type(request, expected_content_type=JSON_CONTENT_TYPE)
    f_kwargs = await RoleModel.get_kwargs(request)

    dapi = DistributedAPI(f=security.add_role,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def remove_roles(role_ids: list = None, pretty: bool = False,
                       wait_for_complete: bool = False) -> ConnexionResponse:
    """Removes a list of roles in the system.

    Parameters
    ----------
    role_ids : list, optional
        List of roles ids to be deleted.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response composed of two lists: one contains the deleted roles and the other the non-deleted roles.
    """
    if 'all' in role_ids:
        role_ids = None
    f_kwargs = {'role_ids': role_ids}

    dapi = DistributedAPI(f=security.remove_roles,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def update_role(role_id: int, pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Update the information of a specified role.

    Parameters
    ----------
    role_id : int
        Specific role id in the system to be updated.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    # Get body parameters
    Body.validate_content_type(request, expected_content_type=JSON_CONTENT_TYPE)
    f_kwargs = await RoleModel.get_kwargs(request, additional_kwargs={'role_id': role_id})

    dapi = DistributedAPI(f=security.update_role,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_rules(rule_ids: list = None, pretty: bool = False, wait_for_complete: bool = False,
                    offset: int = 0, limit: int = None, search: str = None, select: str = None,
                    sort: str = None, q: str = '', distinct: bool = False) -> ConnexionResponse:
    """Get information about the security rules in the system.

    Parameters
    ----------
    rule_ids : list, optional
        List of rule ids to be obtained.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.
    offset : int, optional
        First item to return.
    limit : int, optional
        Maximum number of items to return.
    search : str, optional
        Looks for elements with the specified string.
    select : str
        Select which fields to return (separated by comma).
    sort : str, optional
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    q : str
        Query to filter results by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'rule_ids': rule_ids, 'offset': offset, 'limit': limit, 'select': select,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['id'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'q': q,
                'distinct': distinct
                }

    dapi = DistributedAPI(f=security.get_rules,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def add_rule(pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Add a specified rule.

    Parameters
    ----------
    request : request.connexion
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    # Get body parameters
    Body.validate_content_type(request, expected_content_type=JSON_CONTENT_TYPE)
    f_kwargs = await RuleModel.get_kwargs(request)

    dapi = DistributedAPI(f=security.add_rule,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def update_rule(rule_id: int, pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Update the information of a specified rule.

    Parameters
    ----------
    rule_id : int
        Specific rule id in the system to be updated.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    # Get body parameters
    Body.validate_content_type(request, expected_content_type=JSON_CONTENT_TYPE)
    f_kwargs = await RuleModel.get_kwargs(request, additional_kwargs={'rule_id': rule_id})

    dapi = DistributedAPI(f=security.update_rule,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def remove_rules(rule_ids: list = None, pretty: bool = False,
                       wait_for_complete: bool = False) -> ConnexionResponse:
    """Remove a list of rules from the system.

    Parameters
    ----------
    rule_ids : list, optional
        List of rule ids to be deleted.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response composed of two lists: one contains the deleted rules and the other the non-deleted rules.
    """
    if 'all' in rule_ids:
        rule_ids = None
    f_kwargs = {'rule_ids': rule_ids}

    dapi = DistributedAPI(f=security.remove_rules,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_policies(policy_ids: list = None, pretty: bool = False, wait_for_complete: bool = False,
                       offset: int = 0, limit: int = None, search: str = None, select: str = None,
                       sort: str = None, q: str = None, distinct: bool = False) -> ConnexionResponse:
    """Returns information from all system policies.

    Parameters
    ----------
    policy_ids : list, optional
        List of policies.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.
    offset : int, optional
        First item to return.
    limit : int, optional
        Maximum number of items to return.
    search : str, optional
        Looks for elements with the specified string.
    select : str
        Select which fields to return (separated by comma).
    sort : str, optional
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    q : str
        Query to filter results by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response with the policies information.
    """
    f_kwargs = {'policy_ids': policy_ids, 'offset': offset, 'limit': limit, 'select': select,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['id'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'q': q,
                'distinct': distinct
                }

    dapi = DistributedAPI(f=security.get_policies,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def add_policy(pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Add a specified policy.

    Parameters
    ----------
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    # Get body parameters
    Body.validate_content_type(request, expected_content_type=JSON_CONTENT_TYPE)
    f_kwargs = await PolicyModel.get_kwargs(request)

    dapi = DistributedAPI(f=security.add_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def remove_policies(policy_ids: list = None, pretty: bool = False,
                          wait_for_complete: bool = False) -> ConnexionResponse:
    """Removes a list of roles in the system.

    Parameters
    ----------
    policy_ids : list, optional
        List of policies ids to be deleted.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response composed of two lists: one contains the deleted policies and the other the non-deleted policies.
    """
    if 'all' in policy_ids:
        policy_ids = None
    f_kwargs = {'policy_ids': policy_ids}

    dapi = DistributedAPI(f=security.remove_policies,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def update_policy(policy_id: int, pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Update the information of a specified policy.

    Parameters
    ----------
    policy_id : int
        Specific policy id in the system to be updated
    pretty : bool, optional
        Show results in human-readable format
    wait_for_complete : bool, optional
        Disable timeout response

    Returns
    -------
    ConnexionResponse
        API response.
    """
    # Get body parameters
    Body.validate_content_type(request, expected_content_type=JSON_CONTENT_TYPE)
    f_kwargs = await PolicyModel.get_kwargs(request, additional_kwargs={'policy_id': policy_id})

    dapi = DistributedAPI(f=security.update_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def set_user_role(user_id: str, role_ids: list, position: int = None,
                        pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Add a list of roles to a specified user.

    Parameters
    ----------
    user_id : str
        User ID.
    role_ids : list
        List of role ids.
    position : int, optional
        Position where the new role will be inserted.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'user_id': user_id, 'role_ids': role_ids, 'position': position}
    dapi = DistributedAPI(f=security.set_user_role,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def remove_user_role(user_id: str, role_ids: list, pretty: bool = False,
                           wait_for_complete: bool = False) -> ConnexionResponse:
    """Delete a list of roles of a specified user.

    Parameters
    ----------
    user_id : str
        User ID.
    role_ids : list
        List of roles ids.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete: bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    if 'all' in role_ids:
        role_ids = None
    f_kwargs = {'user_id': user_id, 'role_ids': role_ids}

    dapi = DistributedAPI(f=security.remove_user_role,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def set_role_policy(role_id: int, policy_ids: list, position: int = None, pretty: bool = False,
                          wait_for_complete: bool = False) -> ConnexionResponse:
    """Add a list of policies to a specified role.

    Parameters
    ----------
    role_id : int
        Role ID.
    policy_ids : list
        List of policy IDs.
    position : int
        Position where the new role will be inserted.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'role_id': role_id, 'policy_ids': policy_ids, 'position': position}

    dapi = DistributedAPI(f=security.set_role_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def remove_role_policy(role_id: int, policy_ids: list, pretty: bool = False,
                             wait_for_complete: bool = False) -> ConnexionResponse:
    """Delete a list of policies of a specified role.

    Parameters
    ----------
    request : request.connexion
    role_id : int
        Role ID.
    policy_ids : list
        List of policy ids.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    if 'all' in policy_ids:
        policy_ids = None
    f_kwargs = {'role_id': role_id, 'policy_ids': policy_ids}

    dapi = DistributedAPI(f=security.remove_role_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def set_role_rule(role_id: int, rule_ids: list, pretty: bool = False,
                        wait_for_complete: bool = False) -> ConnexionResponse:
    """Add a list of rules to a specified role.

    Parameters
    ----------
    request : request.connexion
    role_id : int
        Role ID.
    rule_ids : list
        List of rule IDs.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'role_id': role_id, 'rule_ids': rule_ids,
                'run_as': {'user': request.context['token_info']['sub'], 'run_as': request.context['token_info']['run_as']}}

    dapi = DistributedAPI(f=security.set_role_rule,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def remove_role_rule(role_id: int, rule_ids: list, pretty: bool = False,
                           wait_for_complete: bool = False) -> ConnexionResponse:
    """Delete a list of rules of a specified role.

    Parameters
    ----------
    request : request.connexion
    role_id : int
        Role ID.
    rule_ids : list
        List of rule ids.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    if 'all' in rule_ids:
        rule_ids = None
    f_kwargs = {'role_id': role_id, 'rule_ids': rule_ids}

    dapi = DistributedAPI(f=security.remove_role_rule,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_rbac_resources(resource: str = None, pretty: bool = False) -> ConnexionResponse:
    """Gets all the current defined resources for RBAC.

    Parameters
    ----------
    resource : str, optional
        Show the information of the specified resource. Ex: agent:id
    pretty : bool, optional
        Show results in human-readable format.

    Returns
    -------
    ConnexionResponse
        API response with the RBAC resources.
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

    return json_response(data, pretty=pretty)


async def get_rbac_actions(pretty: bool = False, endpoint: str = None) -> ConnexionResponse:
    """Gets all the current defined actions for RBAC.

    Parameters
    ----------
    pretty : bool, optional
        Show results in human-readable format.
    endpoint : str, optional
        Show actions and resources for the specified endpoint. Ex: GET /agents

    Returns
    -------
    ConnexionResponse
        API response with the RBAC actions.
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

    return json_response(data, pretty=pretty)


async def revoke_all_tokens(pretty: bool = False) -> ConnexionResponse:
    """Revoke all tokens.

    Parameters
    ----------
    request : request.connexion
    pretty : bool, optional
        Show results in human-readable format.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {}

    nodes = await get_system_nodes()
    if isinstance(nodes, Exception):
        nodes = None

    dapi = DistributedAPI(f=security.wrapper_revoke_tokens,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master' if nodes is not None else 'local_any',
                          is_async=False,
                          broadcasting=nodes is not None,
                          wait_for_complete=True,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          nodes=nodes
                          )
    data = raise_if_exc(await dapi.distribute_function())
    if type(data) == AffectedItemsWazuhResult and len(data.affected_items) == 0:
        raise_if_exc(WazuhPermissionError(4000, data.message))

    return json_response(data, pretty=pretty)


async def get_security_config(pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Get active security configuration.

    Parameters
    ----------
    request : request.connexion
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=security.get_security_config,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def security_revoke_tokens():
    """Revokes all tokens on all nodes after a change in security configuration."""
    nodes = await get_system_nodes()
    if isinstance(nodes, Exception):
        nodes = None

    dapi = DistributedAPI(f=revoke_tokens,
                          request_type='distributed_master' if nodes is not None else 'local_any',
                          is_async=False,
                          wait_for_complete=True,
                          broadcasting=nodes is not None,
                          logger=logger,
                          nodes=nodes
                          )
    raise_if_exc(await dapi.distribute_function())


async def put_security_config(pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Update current security configuration with the given one

    Parameters
    ----------
    request : request.connexion
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    Body.validate_content_type(request, expected_content_type=JSON_CONTENT_TYPE)
    f_kwargs = {'updated_config': await SecurityConfigurationModel.get_kwargs(request)}

    dapi = DistributedAPI(f=security.update_security_config,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())
    await security_revoke_tokens()

    return json_response(data, pretty=pretty)


async def delete_security_config(pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Restore default security configuration.

    Parameters
    ----------
    request : request.connexion
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {"updated_config":
                await SecurityConfigurationModel.get_kwargs(request,
                                                            default_security_configuration)}

    dapi = DistributedAPI(f=security.update_security_config,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())
    await security_revoke_tokens()

    return json_response(data, pretty=pretty)
