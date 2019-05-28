

# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging

from connexion.lifecycle import ConnexionResponse

from api.models.base_model_ import Data
from api.util import remove_nones_to_dict, exception_handler, parse_api_param, raise_if_exc
from wazuh.cluster.dapi.dapi import DistributedAPI
from wazuh.rbac import Role
from wazuh.exception import WazuhError, WazuhInternalError


loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
def get_roles(pretty=False, wait_for_complete=False, offset=0, limit=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    """

    f_kwargs = {'offset': offset, 'limit': limit}

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
def get_role(role_id, pretty=False, wait_for_complete=False, offset=0, limit=None):
    """
    :param role_id: Specified role
    :type role_id: int
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
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
    response = Data(data)

    return response, 200


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
