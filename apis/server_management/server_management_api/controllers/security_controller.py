# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from connexion import request
from connexion.lifecycle import ConnexionResponse
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.exception import WazuhException
from wazuh.core.results import WazuhResult
from wazuh.rbac import preprocessor

from server_management_api.authentication import generate_token
from server_management_api.controllers.util import JSON_CONTENT_TYPE
from server_management_api.encoder import dumps
from server_management_api.models.security_token_response_model import TokenResponseModel
from server_management_api.util import raise_if_exc, remove_nones_to_dict

logger = logging.getLogger('wazuh-api')


async def login_user(user: str, raw: bool = False) -> ConnexionResponse:
    """User/password authentication to get an access token.
    This method should be called to get an API token. This token will expire at some time.

    Parameters
    ----------
    user : str
        Name of the user who wants to be authenticated.
    raw : bool, optional
        Respond in raw format. Default `False`

    Returns
    -------
    ConnexionResponse
        Raw or JSON response with the generated access token.
    """
    f_kwargs = {'user_id': user}

    dapi = DistributedAPI(
        f=preprocessor.get_permissions,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_master',
        is_async=True,
        logger=logger,
        rbac_manager=request.state.rbac_manager if request else None,
    )
    data = raise_if_exc(await dapi.distribute_function())

    token = None
    try:
        token = generate_token(user_id=user, data=data.dikt)
    except WazuhException as e:
        raise_if_exc(e)

    return (
        ConnexionResponse(body=token, content_type='text/plain', status_code=200)
        if raw
        else ConnexionResponse(
            body=dumps(WazuhResult({'data': TokenResponseModel(token=token)})),
            content_type=JSON_CONTENT_TYPE,
            status_code=200,
        )
    )


async def run_as_login(user: str, raw: bool = False) -> ConnexionResponse:
    """User/password authentication to get an access token.
    This method should be called to get an API token using an authorization context body. This token will expire at
    some time.

    Parameters
    ----------
    user : str
        Name of the user who wants to be authenticated.
    raw : bool, optional
        Respond in raw format. Default `False`

    Returns
    -------
    ConnexionResponse
        Raw or JSON response with the generated access token.
    """
    auth_context = await request.json()
    f_kwargs = {'user_id': user, 'auth_context': auth_context}

    dapi = DistributedAPI(
        f=preprocessor.get_permissions,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_master',
        is_async=True,
        logger=logger,
        rbac_manager=request.state.rbac_manager if request else None,
    )
    data = raise_if_exc(await dapi.distribute_function())

    token = None
    try:
        token = generate_token(user_id=user, data=data.dikt, auth_context=auth_context)
    except WazuhException as e:
        raise_if_exc(e)

    return (
        ConnexionResponse(body=token, content_type='text/plain', status_code=200)
        if raw
        else ConnexionResponse(
            body=dumps(WazuhResult({'data': TokenResponseModel(token=token)})),
            content_type=JSON_CONTENT_TYPE,
            status_code=200,
        )
    )
