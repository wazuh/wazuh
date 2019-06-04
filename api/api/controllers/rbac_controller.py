

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging
import connexion
from api.models.base_model_ import Data
from api.util import remove_nones_to_dict, exception_handler, raise_if_exc, parse_api_param
from wazuh.cluster.dapi.dapi import DistributedAPI
from wazuh.rbac import Role, Policy, RolePolicy
from wazuh.exception import WazuhError, WazuhInternalError


loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
def get_roles(pretty=False, wait_for_complete=False, offset=0, limit=None, search=None, sort=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    """

    f_kwargs = {'offset': offset, 'limit': limit,
                'search': parse_api_param(search, 'search'),
                'sort': parse_api_param(sort, 'sort')}

    dapi = DistributedAPI(f=Role.get_roles,
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
    """
    :param role_id: Specified role
    :type role_id: int
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    """

    f_kwargs = {'role_id': role_id}

    dapi = DistributedAPI(f=Role.get_role,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    # response = Data(data)

    return data, 200


@exception_handler
def add_role(pretty=False, wait_for_complete=False):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
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

    dapi = DistributedAPI(f=Role.add_role,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    # response = Data(data)

    return data, 200


@exception_handler
def remove_role(role_id, pretty=False, wait_for_complete=False):
    """
    :param role_id: Role to be delete
    :type role_id: int
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    """

    f_kwargs = {'role_id': role_id}

    dapi = DistributedAPI(f=Role.remove_role,
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
def remove_roles(list_roles=list(), pretty=False, wait_for_complete=False):
    """
    :param list_roles: List of roles to delete
    :type list_roles: list
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    """

    f_kwargs = {'list_roles': list_roles}

    dapi = DistributedAPI(f=Role.remove_roles,
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
    """
    :param role_id: Role id to be update
    :type role_id: int
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
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

    dapi = DistributedAPI(f=Role.update_role,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    # response = Data(data)

    return data, 200


@exception_handler
def get_policies(pretty=False, wait_for_complete=False, offset=0, limit=None, search=None, sort=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    """

    f_kwargs = {'offset': offset, 'limit': limit,
                'search': parse_api_param(search, 'search'),
                'sort': parse_api_param(sort, 'sort')}

    dapi = DistributedAPI(f=Policy.get_policies,
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
    """
    :param policy_id: Specified policy
    :type policy_id: int
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    """

    f_kwargs = {'policy_id': policy_id}

    dapi = DistributedAPI(f=Policy.get_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    # response = Data(data)

    return data, 200


@exception_handler
def add_policy(pretty=False, wait_for_complete=False):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    """

    # get body parameters
    if connexion.request.is_json:
        policy_added_model = connexion.request.get_json()
    else:
        raise WazuhError(1749, extra_remediation='[official documentation]'
                                                 '(TO BE DEFINED) '
                                                 'to get more information about API call')

    f_kwargs = policy_added_model

    dapi = DistributedAPI(f=Policy.add_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    # response = Data(data)

    return data, 200


@exception_handler
def remove_policy(policy_id, pretty=False, wait_for_complete=False):
    """
    :param policy_id: Policy to be delete
    :type policy_id: int
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    """

    f_kwargs = {'policy_id': policy_id}

    dapi = DistributedAPI(f=Policy.remove_policy,
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
def remove_policies(list_policies=list(), pretty=False, wait_for_complete=False):
    """
    :param list_policies: List of policies to delete
    :type list_policies: list
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    """

    f_kwargs = {'list_policies': list_policies}

    dapi = DistributedAPI(f=Policy.remove_policies,
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
    """
    :param policy_id: Policy id to be update
    :type policy_id: int
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
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

    dapi = DistributedAPI(f=Policy.update_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    # response = Data(data)

    return data, 200


@exception_handler
def set_role_policy(role_id, policy_id, pretty=False, wait_for_complete=False):
    """
    :param role_id: Role id
    :type role_id: int
    :param policy_id: Policy id
    :type policy_id: int
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    """

    f_kwargs = {'role_id': role_id, 'policy_id': policy_id}

    dapi = DistributedAPI(f=RolePolicy.set_role_policy,
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
def remove_role_policy(role_id, policy_id, pretty=False, wait_for_complete=False):
    """
    :param role_id: Role id
    :type role_id: int
    :param policy_id: Policy id
    :type policy_id: int
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    """

    f_kwargs = {'role_id': role_id, 'policy_id': policy_id}

    dapi = DistributedAPI(f=RolePolicy.remove_role_policy,
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
