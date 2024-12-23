# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from connexion import request
from connexion.lifecycle import ConnexionResponse
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.order import send_orders

from api.controllers.util import JSON_CONTENT_TYPE, json_response
from api.models.base_model_ import Body
from api.models.order_model import Orders
from api.util import raise_if_exc, remove_nones_to_dict

logger = logging.getLogger('wazuh-api')


async def post_orders(pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Send orders to the local server to distribute them.

    Parameters
    ----------
    request : web.Request
        API Request.
    pretty : bool, optional
        Show results in human-readable format, by default False.
    wait_for_complete : bool, optional
        Disable timeout response, by default False.

    Returns
    -------
    ConnexionResponse
        API Response.
    """
    Body.validate_content_type(request, expected_content_type=JSON_CONTENT_TYPE)
    f_kwargs = await Orders.get_kwargs(request)

    dapi = DistributedAPI(
        f=send_orders,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_any',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies'],
    )

    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
