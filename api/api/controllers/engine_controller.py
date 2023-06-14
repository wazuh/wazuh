
# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from aiohttp import web

from api.encoder import dumps, prettify
from api.util import raise_if_exc, remove_nones_to_dict
from wazuh import engine
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from api.models.base_model_ import Body
from api.models.engine_model import PolicyIntegrationModel

logger = logging.getLogger('wazuh-api')

# @expose_resources(actions=["engine:add_integration_policy"], resources=["engine:config:*"])
async def add_integration_policy(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Get the runtime configuration of the manager.
    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    web.Response
        API response.
    """
    Body.validate_content_type(request, expected_content_type='application/json')
    f_kwargs = await PolicyIntegrationModel.get_kwargs(request)

    dapi = DistributedAPI(f=engine.add_integration_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)

# @expose_resources(actions=["engine:remove_integration_policy"], resources=["engine:config:*"])
async def remove_integration_policy(request, policy: str, integration: str, pretty: bool = False, 
                                    wait_for_complete: bool = False) -> web.Response:
    """Update the runtime configuration of the manager.
    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {
        'policy': policy,
        'integration': integration
    }
    dapi = DistributedAPI(f=engine.remove_integration_policy,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)