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

logger = logging.getLogger("wazuh-api")


async def upsert_integration(
    body: dict, type_: str, pretty: bool = False, wait_for_complete: bool = False
) -> ConnexionResponse:
    """Create a new integration.

    Parameters
    ----------
    type_ : str
        Policy type.
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
    parsed_body = await IntegrationCreateModel.get_kwargs(body)

    f_kwargs = {"integration_content": parsed_body, "policy_type": type_}

    dapi = DistributedAPI(
        f=integration.upsert_integration,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type="local_master",
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context["token_info"]["rbac_policies"],
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_integration(
    integration_id: list = None,
    type_: str = None,
    status: str = None,
    pretty: bool = False,
    wait_for_complete: bool = False,
    offset: int = 0,
    limit: int = None,
    select: list = None,
    sort: str = None,
    search: str = None,
    q: str = None,
    distinct: bool = False,
) -> ConnexionResponse:
    """Get all decoders.

    Parameters
    ----------
    integration_id : list
        Filters by integration id.
    type_: str
        Policy type.
    status : str
        Filters by status.
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    search : str
        Look for elements with the specified string.
    q : str
        Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;active&amp;quot;
    distinct : bool
        Look for distinct values.
    Returns
    -------
    ConnexionResponse
        API response.
    """

    ids = integration_id or []

    f_kwargs = {
        "ids": ids,
        "offset": offset,
        "limit": limit,
        "select": select,
        "sort_by": parse_api_param(sort, "sort")["fields"] if sort is not None else ["id"],
        "sort_ascending": True if sort is None or parse_api_param(sort, "sort")["order"] == "asc" else False,
        "search_text": parse_api_param(search, "search")["value"] if search is not None else None,
        "complementary_search": parse_api_param(search, "search")["negation"] if search is not None else None,
        "q": q,
        "status": status,
        "distinct": distinct,
        "policy_type": type_,
    }

    dapi = DistributedAPI(
        f=integration.get_integration,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type="local_any",
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context["token_info"]["rbac_policies"],
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def delete_integration(
    type_: str, integration_id: List[str], pretty: bool = False, wait_for_complete: bool = False
) -> ConnexionResponse:
    """Delete one or more integrations.

    Parameters
    ----------
    type_ : str
        Policy type.
    integration_id : List[str]
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
    f_kwargs = {"policy_type": type_, "ids": integration_id}

    dapi = DistributedAPI(
        f=integration.delete_integration,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type="local_master",
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context["token_info"]["rbac_policies"],
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
