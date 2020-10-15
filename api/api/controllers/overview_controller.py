# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from aiohttp import web

from api.encoder import dumps, prettify
from api.util import raise_if_exc, remove_nones_to_dict
from wazuh.agent import get_full_overview
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh')


async def get_overview_agents(request, pretty=False, wait_for_complete=False):
    """ Get full summary of agents.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :return: Dict with a full summary of agents
    """
    f_kwargs = {}

    dapi = DistributedAPI(f=get_full_overview,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
