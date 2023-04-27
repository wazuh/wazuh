# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging

from aiohttp import web
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.results import WazuhResult
from wazuh.event import send_event_to_analysisd

from api.encoder import dumps, prettify
from api.models.base_model_ import Body
from api.api.models.events_ingest_model import EventsIngestModel
from api.util import remove_nones_to_dict

logger = logging.getLogger('wazuh-api')


async def forward_event(request, pretty=False, wait_for_complete=False):
    Body.validate_content_type(request, expected_content_type='application/json')
    f_kwargs = await EventsIngestModel.get_kwargs(request)

    dapi = DistributedAPI(
        f=send_event_to_analysisd,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_master',
        is_async=False,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request['token_info']['rbac_policies']
    )

    asyncio.create_task(dapi.distribute_function())

    data = WazuhResult({'message': 'The events will be forwarded to analisysd'})

    return web.json_response(data=data, status=202, dumps=prettify if pretty else dumps)
