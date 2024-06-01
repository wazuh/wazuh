# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from connexion import request
from connexion.lifecycle import ConnexionResponse

from api.controllers.util import json_response, JSON_CONTENT_TYPE
from api.models.base_model_ import Body
from api.models.logtest_model import LogtestModel
from api.util import remove_nones_to_dict, raise_if_exc

from wazuh import logtest
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh-api')


async def run_logtest_tool(pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Get the logtest output after sending a JSON to its socket.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    Body.validate_content_type(request, expected_content_type=JSON_CONTENT_TYPE)
    f_kwargs = await LogtestModel.get_kwargs(request)

    dapi = DistributedAPI(f=logtest.run_logtest,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def end_logtest_session(pretty: bool = False, wait_for_complete: bool = False,
                              token: str = None) -> ConnexionResponse:
    """Delete the saved session corresponding to the specified token.

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
    ConnexionResponse
        API response.
    """
    f_kwargs = {'token': token}

    dapi = DistributedAPI(f=logtest.end_logtest_session,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
