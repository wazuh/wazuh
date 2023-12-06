# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from connexion import request
from connexion.lifecycle import ConnexionResponse
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.event import send_event_to_analysisd

from api.controllers.util import json_response, JSON_CONTENT_TYPE
from api.models.base_model_ import Body
from api.models.event_ingest_model import EventIngestModel
from api.util import raise_if_exc, remove_nones_to_dict

logger = logging.getLogger('wazuh-api')


async def forward_event(pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Forward events to analysisd.

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
    f_kwargs = await EventIngestModel.get_kwargs(request)

    dapi = DistributedAPI(f=send_event_to_analysisd,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
