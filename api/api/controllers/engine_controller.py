# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from typing import Optional
from aiohttp import web

from api.encoder import dumps, prettify
from api.util import raise_if_exc, remove_nones_to_dict, parse_api_param
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from api.models.base_model_ import Body
from api.models.engine_route_model import RouteUpdateModel, RouteCreateModel
from wazuh import engine_router


logger = logging.getLogger('wazuh-api')

HARDCODED_VALUE_TO_SPECIFY = 100


async def get_routes(request, name: Optional[str] = None,
                      select: Optional[str] = None, sort: Optional[str] = None, search: Optional[str] = None,
                      offset: int = 0, limit: int = HARDCODED_VALUE_TO_SPECIFY, pretty: bool = False,
                      wait_for_complete: bool = False):

    f_kwargs = {
        'name': name,
        'select': select,
        'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else None,
        'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
        'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
        'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
        'offset': offset,
        'limit': limit
    }

    dapi = DistributedAPI(f=engine_router.get_routes,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())
    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def create_route(request, pretty: bool = False, wait_for_complete: bool = False):
    Body.validate_content_type(request, expected_content_type='application/json')
    f_kwargs = await RouteCreateModel.get_kwargs(request)

    dapi = DistributedAPI(f=engine_router.create_route,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())
    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def update_route(request, pretty: bool = False, wait_for_complete: bool = False):
    Body.validate_content_type(request, expected_content_type='application/json')
    f_kwargs = await RouteUpdateModel.get_kwargs(request)

    dapi = DistributedAPI(f=engine_router.update_route,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())
    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def delete_route(request, name: Optional[str] = None, pretty: bool = False, wait_for_complete: bool = False):
    f_kwargs = {'name': name}

    dapi = DistributedAPI(f=engine_router.delete_route,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )

    data = raise_if_exc(await dapi.distribute_function())
    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
