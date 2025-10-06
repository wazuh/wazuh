# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from typing import List, Optional
from connexion import request
from connexion.lifecycle import ConnexionResponse

from api.controllers.util import json_response, JSON_CONTENT_TYPE
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from api.models.base_model_ import Body
from api.models.integration_model import IntegrationCreateModel
from wazuh import integration
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.engine.models.integration import Integration

logger = logging.getLogger('wazuh-api')

async def create_integration(type_: str, pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Create a new integration.

    Parameters
    ----------
    type_ : str
        Integration type.
    pretty : bool, optional
        Show results in human-readable format. Default `False`.
    wait_for_complete : bool, optional
        Disable timeout response. Default `False`.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    Body.validate_content_type(request, expected_content_type=JSON_CONTENT_TYPE)
    body_dict = await IntegrationCreateModel.get_kwargs(request)
    model = Integration(**body_dict)

    f_kwargs = {
        'integration': model,
        'policy_type': type_
    }

    dapi = DistributedAPI(
        f=integration.create_integration,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_master',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies']
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)

async def get_integrations(type_: str, integrations_list: List[str], status: Optional[str] = None,
                           search: Optional[str] = None, pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Get integrations.

    Parameters
    ----------
    type_ : str
        Integration type.
    integrations_list : List[str]
        List of integration names to retrieve.
    status : str, optional
        Filter by integration status.
    search : str, optional
        Search string to filter integrations.
    pretty : bool, optional
        Show results in human-readable format. Default `False`.
    wait_for_complete : bool, optional
        Disable timeout response. Default `False`.

    Returns
    -------
    ConnexionResponse
        API response with the list of integrations.
    """
    f_kwargs = {
        'policy_type': type_,
        'names': integrations_list,
        'status': status,
        'search': parse_api_param(search, 'search')['value'] if search is not None else None,
    }

    dapi = DistributedAPI(
        f=integration.get_integrations,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_master',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies']
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)

async def update_integration(type_: str, pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Update an existing integration.

    Parameters
    ----------
    type_ : str
        Integration type.
    pretty : bool, optional
        Show results in human-readable format. Default `False`.
    wait_for_complete : bool, optional
        Disable timeout response. Default `False`.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    Body.validate_content_type(request, expected_content_type=JSON_CONTENT_TYPE)
    body_dict = await IntegrationCreateModel.get_kwargs(request)
    model = Integration(**body_dict)

    f_kwargs = {
        'integration': model,
        'policy_type': type_
    }

    dapi = DistributedAPI(
        f=integration.update_integration,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_master',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies']
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)

async def delete_integration(type_: str, integrations_list: List[str], pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Delete one or more integrations.

    Parameters
    ----------
    type_ : str
        Integration type.
    integrations_list : List[str]
        List of integration names to delete.
    pretty : bool, optional
        Show results in human-readable format. Default `False`.
    wait_for_complete : bool, optional
        Disable timeout response. Default `False`.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {
        'policy_type': type_,
        'integrations_list': integrations_list
    }

    dapi = DistributedAPI(
        f=integration.delete_integration,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_master',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies']
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
