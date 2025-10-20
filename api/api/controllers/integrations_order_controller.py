# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from connexion import request
from connexion.lifecycle import ConnexionResponse

from api.controllers.util import json_response, JSON_CONTENT_TYPE
from api.util import remove_nones_to_dict, raise_if_exc
from api.models.base_model_ import Body
from api.models.integrations_order_model import IntegrationsOrderModel, IntegrationInfoModel
from wazuh import integrations_order
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.engine.models.integrations_order import IntegrationsOrder, IntegrationInfo

logger = logging.getLogger("wazuh-api")


async def upsert_integrations_order(
    body: dict, type_: str, pretty: bool = False, wait_for_complete: bool = False
) -> ConnexionResponse:
    """Upsert integrations order.

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
    orders_create_model = IntegrationsOrderModel(
        order=[IntegrationInfoModel(id=order["id"], name=order["name"]) for order in body]
    )
    model = IntegrationsOrder(
        order=[IntegrationInfo(id=order.id, name=order.name) for order in orders_create_model.order]
    )

    f_kwargs = {"order": model, "policy_type": type_}

    dapi = DistributedAPI(
        f=integrations_order.upsert_integrations_order,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type="local_master",
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context["token_info"]["rbac_policies"],
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_integrations_order(type_: str, pretty: bool = False, wait_for_complete: bool = False):
    """Get the integrations order.

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
        API response with the integrations order.
    """
    f_kwargs = {"policy_type": type_}

    dapi = DistributedAPI(
        f=integrations_order.get_integrations_order,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type="local_any",
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context["token_info"]["rbac_policies"],
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def delete_integrations_order(type_: str, pretty: bool = False, wait_for_complete: bool = False):
    """Delete the integrations order.

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
    f_kwargs = {
        "policy_type": type_,
    }

    dapi = DistributedAPI(
        f=integrations_order.delete_integrations_order,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type="local_master",
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context["token_info"]["rbac_policies"],
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
