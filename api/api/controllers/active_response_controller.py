# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from aiohttp import web

import wazuh.active_response as active_response
from api.encoder import dumps, prettify
from api.models.active_response_model import ActiveResponseModel
from api.models.base_model_ import Body
from api.util import remove_nones_to_dict, raise_if_exc
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh-api')


async def run_command(request, agents_list='*', pretty=False, wait_for_complete=False):
    """Runs an Active Response command on a specified agent

    :param agents_list: List of Agents IDs. All possible values from 000 onwards
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return: message
    """
    # Get body parameters
    Body.validate_content_type(request, expected_content_type='application/json')
    f_kwargs = await ActiveResponseModel.get_kwargs(request, additional_kwargs={'agent_list': agents_list})

    dapi = DistributedAPI(f=active_response.run_command,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=agents_list == '*',
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
