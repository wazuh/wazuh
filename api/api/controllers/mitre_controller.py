# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from aiohttp import web

import wazuh.mitre as mitre
from api.encoder import dumps, prettify
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh.core.common import database_limit
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh-api')


async def get_attack(request, pretty=False, wait_for_complete=False, offset=0, limit=database_limit,
                     phase_name=None, platform_name=None, q=None, search=None, select=None, sort=None):
    """Get information from MITRE ATT&CK database

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param phase_name: Filters by phase
    :param platform_name: Filters by platform
    :param search: Search if the string is contained in the db
    :param offset: First item to return
    :param limit: Maximum number of items to return
    :param sort: Sort the items. Format: {'fields': ['field1', 'field2'], 'order': 'asc|desc'}
    :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
    :param q: Query to filter by
    :return: Data
    """
    f_kwargs = {'id_': request.query.get('id', None),
                'phase_name': phase_name,
                'platform_name': platform_name,
                'select': select,
                'search': parse_api_param(search, 'search'),
                'offset': offset,
                'limit': limit,
                'sort': parse_api_param(sort, 'sort'),
                'q': q
                }

    dapi = DistributedAPI(f=mitre.get_attack,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
