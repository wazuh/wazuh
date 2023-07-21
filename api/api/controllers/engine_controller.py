# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from aiohttp import web

from api.encoder import dumps, prettify
from api.util import raise_if_exc, remove_nones_to_dict, parse_api_param
from wazuh import engine
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from api.models.base_model_ import Body

logger = logging.getLogger('wazuh-api')

# @expose_resources(actions=["engine:read_graph"], resources=["engine:graph:*"])
async def get_graph_resource(request, policy: str, graph_type: str, pretty: bool = False, 
                              wait_for_complete: bool = False) -> web.Response:
    """Get a resource from the graph.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    policy : str
        Name of the policy.
    graph_type : str
        Type of graph.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {
        'policy': policy,
        'graph_type': graph_type,
        }

    dapi = DistributedAPI(f=engine.get_graph_resource,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
