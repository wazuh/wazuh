# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging
import re

import connexion

from api.authentication import generate_token
from api.models.base_model_ import Data
from api.models.token_response import TokenResponse
from api.util import remove_nones_to_dict, exception_handler, raise_if_exc, parse_api_param
from wazuh.cluster.dapi.dapi import DistributedAPI
from wazuh.exception import WazuhError
from wazuh import security

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
def get_roles(pretty=False, wait_for_complete=False, offset=0, limit=None, search=None, sort=None):
    """Returns information from all system roles

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :return Roles information
    """
    f_kwargs = {'offset': offset, 'limit': limit,
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
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_role(role_id, pretty=False, wait_for_complete=False):
    """Return the information from a system role

    :param role_id: Id of the role to be obtained
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Role information
    """
    f_kwargs = {'role_id': role_id}

    dapi = DistributedAPI(f=security.get_role,
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
def remove_role(role_id, pretty=False, wait_for_complete=False):
    """Remove one specified role

    :param role_id: Specific role id in the system to be deleted
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Operation result
    """
    f_kwargs = {'role_id': role_id}

    dapi = DistributedAPI(f=security.remove_role,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def remove_roles(list_roles=None, pretty=False, wait_for_complete=False):
    """Removes a list of roles in the system

    :param list_roles: List of roles ids to be deleted
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Two list with deleted roles and not deleted roles
    """
    f_kwargs = {'list_roles': list_roles}

    dapi = DistributedAPI(f=security.remove_roles,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


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

    # f_kwargs = {'role_id': role_id, **{}, **role_added_model.to_dict()}
    role_added_model['role_id'] = role_id
    f_kwargs = role_added_model

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
def get_policies(pretty=False, wait_for_complete=False, offset=0, limit=None, search=None, sort=None):
    """Returns information from all system policies

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :return Policies information
    """
    f_kwargs = {'offset': offset, 'limit': limit,
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
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_policy(policy_id, pretty=False, wait_for_complete=False):
    """Return information of one specified policy

    :param policy_id: Id of the policy to be obtained
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Policy information
    """
    f_kwargs = {'policy_id': policy_id}

    dapi = DistributedAPI(f=security.get_policy,
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
def remove_policy(policy_id, pretty=False, wait_for_complete=False):
    """Removes one specified policy from the system

    :param policy_id: Specific policy id in the system to be deleted
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Operation result
    """
    f_kwargs = {'policy_id': policy_id}

    dapi = DistributedAPI(f=security.remove_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def remove_policies(list_policies=None, pretty=False, wait_for_complete=False):
    """Removes a list of policies in the system

    :param list_policies: List of policies ids to deleted
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Two list with deleted policies and not deleted policies
    """
    f_kwargs = {'list_policies': list_policies}

    dapi = DistributedAPI(f=security.remove_policies,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


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

    policy_added_model['policy_id'] = policy_id
    f_kwargs = policy_added_model

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
def set_role_policy(role_id, policies_ids, pretty=False, wait_for_complete=False):
    """Add a list of policies to one specified role

    :param role_id: Role id
    :param policies_ids: List of policies ids
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Role information
    """
    f_kwargs = {'role_id': role_id, 'policies_ids': policies_ids}

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
def remove_role_policy(role_id, policies_ids, pretty=False, wait_for_complete=False):
    """Delete a list of policies of one specified role

    :param role_id: Role id
    :param policies_ids: List of policies ids
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return Role information
    """
    f_kwargs = {'role_id': role_id, 'policies_ids': policies_ids}

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
