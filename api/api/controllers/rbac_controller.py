

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
def get_roles(pretty=False, wait_for_complete=False):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    """

    dapi = DistributedAPI(f=Role.get_roles,
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


# @exception_handler
# def get_role(role_name=None, pretty=False, wait_for_complete=False):
#     """
#     :param role_name: Specified role
#     :type role_name: str
#     :param pretty: Show results in human-readable format
#     :type pretty: bool
#     :param wait_for_complete: Disable timeout response
#     :type wait_for_complete: bool
#     """
#     f_kwargs = {'role_name': role_name}
#
#     dapi = DistributedAPI(f=get_role,
#                           f_kwargs=remove_nones_to_dict(f_kwargs),
#                           request_type='local_master',
#                           is_async=False,
#                           wait_for_complete=wait_for_complete,
#                           pretty=pretty,
#                           logger=logger
#                           )
#     data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
#     response = Data(data)
#
#     return response, 200