# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from aiohttp import web

from api.encoder import dumps, prettify
from api.models.base_model_ import Body
from api.models.logtest_model import LogtestModel
from api.util import remove_nones_to_dict, raise_if_exc
from wazuh import logtest
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh-api')


async def run_logtest_tool(request, pretty: bool = False, wait_for_complete: bool = False) -> web.Response:
    """Get the logtest output after sending a JSON to its socket.

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
    f_kwargs = await LogtestModel.get_kwargs(request)

    dapi = DistributedAPI(f=logtest.run_logtest,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def end_logtest_session(request, pretty: bool = False, wait_for_complete: bool = False,
                              token: str = None) -> web.Response:
    """Delete the saved session corresponding to the specified token.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    token : str
        Token of the saved session.
        
    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'token': token}

    dapi = DistributedAPI(f=logtest.end_logtest_session,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
