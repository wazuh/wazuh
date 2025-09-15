# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from connexion import request
from connexion.lifecycle import ConnexionResponse

from api.controllers.util import json_response
from api.models.base_model_ import Body
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh import kvdb_list
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.results import AffectedItemsWazuhResult

logger = logging.getLogger('wazuh-api')


async def get_lists(pretty: bool = False, wait_for_complete: bool = False, offset: int = 0, limit: int = None,
                    select: list = None, sort: str = None, search: str = None, q: str = None,
                    distinct: bool = False) -> ConnexionResponse:
    """Get all user-defined KVDBs.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : list
        Select which fields to return (separated by comma).
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning
        to list in ascending or descending order.
    search : str
        Look for elements with the specified string.
    q : str
        Query to filter results by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'offset': offset,
                'select': select,
                'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['name'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'search_in_fields': ['name'],
                'q': q,
                'distinct': distinct
                }

    dapi = DistributedAPI(f=kvdb_list.list_kvdbs,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_kvdb(pretty: bool = False, wait_for_complete: bool = False, kvdb: str = None,
                   select: list = None) -> ConnexionResponse:
    """Get content of one KVDB.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    kvdb : str
        KVDB logical name.
    select : list
        Select which fields to return (separated by comma).

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {
        'name': kvdb,
        'select': select
    }

    dapi = DistributedAPI(f=kvdb_list.get_kvdb,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def put_kvdb(body: dict, pretty: bool = False, wait_for_complete: bool = False,
                   kvdb: str = None) -> ConnexionResponse:
    """Create or replace KVDB content (validate → store → reload).

    Parameters
    ----------
    body : dict
        JSON body with the content to store. Must include the 'payload' field (string).
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    kvdb : str
        KVDB logical name.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {
        'name': kvdb,
        'payload': (body or {}).get('payload')
    }

    dapi = DistributedAPI(f=kvdb_list.put_kvdb,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def delete_kvdb(pretty: bool = False, wait_for_complete: bool = False,
                      kvdb: str = None) -> ConnexionResponse:
    """Delete a KVDB.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    kvdb : str
        KVDB logical name to delete.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'name': kvdb}

    dapi = DistributedAPI(f=kvdb_list.delete_kvdb,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
