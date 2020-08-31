# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from aiohttp import web
from api.encoder import dumps, prettify
from api.util import remove_nones_to_dict, raise_if_exc
# from wazuh import logtest # Uncomment when merged with the logtest functions
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh')


async def run_logtest_tool(request, pretty: bool = False, wait_for_complete: bool = False, token: str = None,
                             log_format: str = None, location: str = None, log: str = None):
    """Get the logtest output after sending a JSON to its socket.
    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    token : str
        Token of the saved session.
    log_format : str
        Format of the log.
    location : str
        Path string.
    log : str
        Request body with the log information.

    Returns
    -------
    Data
        Logtest result after analyzing the event.
    """
    f_kwargs = {'token': token,
                'log_format': log_format,
                'location': location,
                'log': log
                }

    dapi = DistributedAPI(f=logtest.get_logtest_output,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def end_logtest_session(request, pretty: bool = False, wait_for_complete: bool = False, token: str = None):
    """Get the logtest output after sending a JSON to its socket.
    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    token : str
        Token of the saved session.
        
    Returns
    -------
    Data
        Rsult after deleting the saved session corresponding to {token}.
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
