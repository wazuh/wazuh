# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from connexion import request
from connexion.lifecycle import ConnexionResponse

from api.controllers.util import json_response, JSON_CONTENT_TYPE
from api.models.base_model_ import Body
from api.models.content_model import ContentUpsertModel
from api.util import remove_nones_to_dict, raise_if_exc

from wazuh import content
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger("wazuh-api")


async def get_catalog(pretty: bool = False, wait_for_complete: bool = False, space: str = None, asset_type: str = None) -> ConnexionResponse:
    """Get content catalog.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    space : str
        Content space name.
    asset_type : str
        Asset type.

    Returns
    -------
    ConnexionResponse
        API response.
    """

    f_kwargs = {"space": space, "asset_type": asset_type}

    dapi = DistributedAPI(
        f=content.get_catalog,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type="local_master",
        is_async=False,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context["token_info"]["rbac_policies"],
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_asset(
    pretty: bool = False, wait_for_complete: bool = False, space: str = None, asset_uuid: str = None
) -> ConnexionResponse:
    """Get asset by uuid from content space.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    space : str
        Content space name.
    asset_uuid : str
        Asset UUID.

    Returns
    -------
    ConnexionResponse
        API response.
    """

    f_kwargs = {"space": [space], "asset_uuid": [asset_uuid]}

    dapi = DistributedAPI(
        f=content.get_asset,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type="local_master",
        is_async=False,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context["token_info"]["rbac_policies"],
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def delete_asset(
    pretty: bool = False, wait_for_complete: bool = False, space: str = None, asset_uuid: str = None
) -> ConnexionResponse:
    """Delete asset by uuid from content space.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    space : str
        Content space name.
    asset_uuid : str
        Asset UUID.

    Returns
    -------
    ConnexionResponse
        API response.
    """

    f_kwargs = {"space": [space], "asset_uuid": [asset_uuid]}

    dapi = DistributedAPI(
        f=content.delete_asset,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type="local_master",
        is_async=False,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context["token_info"]["rbac_policies"],
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def upsert_asset(pretty: bool = False, wait_for_complete: bool = False, space: str = None) -> ConnexionResponse:
    """Create or update asset in content space.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    space : str
        Content space name.

    Returns
    -------
    ConnexionResponse
        API response.
    """

    Body.validate_content_type(request, expected_content_type=JSON_CONTENT_TYPE)

    f_kwargs = {"asset_data": (await ContentUpsertModel.get_kwargs(request)).get("content"), "space": space}

    dapi = DistributedAPI(
        f=content.upsert_asset,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type="local_master",
        is_async=False,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context["token_info"]["rbac_policies"],
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_integration_order(
    pretty: bool = False, wait_for_complete: bool = False, space: str = None
) -> ConnexionResponse:
    """Get content integration order.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    space : str
        Content space name.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {"space": space}

    dapi = DistributedAPI(
        f=content.get_integration_order,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type="local_master",
        is_async=False,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context["token_info"]["rbac_policies"],
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def update_integration_order(
    pretty: bool = False, wait_for_complete: bool = False, space: str = None
) -> ConnexionResponse:
    """Get content integration order.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    space : str
        Content space name.

    Returns
    -------
    ConnexionResponse
        API response.
    """

    Body.validate_content_type(request, expected_content_type=JSON_CONTENT_TYPE)

    f_kwargs = {"asset_data": (await ContentUpsertModel.get_kwargs(request)).get("content"), "space": space}

    dapi = DistributedAPI(
        f=content.update_integration_order,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type="local_master",
        is_async=False,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context["token_info"]["rbac_policies"],
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
