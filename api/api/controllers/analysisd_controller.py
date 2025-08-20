# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from connexion import request
from connexion.lifecycle import ConnexionResponse

import wazuh.analysisd as analysisd
from api.controllers.util import json_response
from api.util import remove_nones_to_dict, raise_if_exc
from wazuh.core.cluster.control import get_system_nodes
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh-api')


async def put_reload_analysisd(pretty: bool = False, wait_for_complete: bool = False,
                               nodes_list: str = '*') -> ConnexionResponse:
    """Reload the analysisd process on all nodes in the cluster, or a list of them.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    nodes_list : str
        List of node IDs.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'node_list': nodes_list}

    nodes = raise_if_exc(await get_system_nodes())
    dapi = DistributedAPI(f=analysisd.reload_ruleset,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          broadcasting=nodes_list == '*',
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          nodes=nodes
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
