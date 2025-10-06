# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from connexion import request
from connexion.lifecycle import ConnexionResponse

from api.controllers.util import json_response
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from api.models.kvdb_model import KVDBCreateModel, KVDBUpdateModel
from wazuh import kvdb
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh-api')


async def get_kvdbs(pretty: bool = False, wait_for_complete: bool = False,
                    offset: int = 0, limit: int = None, select: list = None,
                    sort: str = None, search: str = None, q: str = None,
                    distinct: bool = False, type_: str = None, kvdb_id: list = None) -> ConnexionResponse:
    """List KVDB resources.

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
    type_ : str
        Policy type. Allowed values: 'testing' | 'production'.
    kvdb_id : list[str]
        Filter by KVDB IDs (e.g. kvdb_id=foo&kvdb_id=bar).

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {
        'policy_type': type_,
        'ids': kvdb_id,
        'offset': offset,
        'limit': limit,
        'select': select,
        'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['id'],
        'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
        'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
        'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
        'search_in_fields': ['id', 'name', 'integration_id'],
        'q': q,
        'distinct': distinct
    }

    dapi = DistributedAPI(
        f=kvdb.list_kvdbs,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_master',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies']
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def post_kvdbs(body: dict, pretty: bool = False, wait_for_complete: bool = False,
                     type_: str = None) -> ConnexionResponse:
    """Create a KVDB.

    Parameters
    ----------
    body : dict
        JSON body with the KVDB item to create. Expected fields:
          - id: str
          - integration_id: str (optional)
          - name: str
          - content: object (K/V map)
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    type_ : str
        Policy type. Allowed values: 'testing' | 'production'.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    model = KVDBCreateModel.from_dict(body)
    f_kwargs = {
        'policy_type': type_,
        'item': model.to_dict()
    }
    
    dapi = DistributedAPI(
        f=kvdb.create_kvdb,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_master',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies']
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def put_kvdbs(body: dict, pretty: bool = False, wait_for_complete: bool = False,
                    type_: str = None) -> ConnexionResponse:
    """Update a KVDB.

    Parameters
    ----------
    body : dict
        JSON body with the KVDB item to update. Expected fields:
          - id: str
          - integration_id: str (optional)
          - name: str (optional)
          - content: object (K/V map)
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    type_ : str
        Policy type. Allowed values: 'testing' | 'production'.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    model = KVDBUpdateModel.from_dict(body)
    f_kwargs = {
        'policy_type': type_,
        'item': model.to_dict()
    }

    dapi = DistributedAPI(
        f=kvdb.update_kvdb,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_master',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies']
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def delete_kvdbs(pretty: bool = False, wait_for_complete: bool = False,
                       type_: str = None, kvdb_id: list = None) -> ConnexionResponse:
    """Delete one or more KVDBs.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    type_ : str
        Policy type. Allowed values: 'testing' | 'production'.
    kvdb_id : list[str]
        KVDB IDs to delete (e.g. kvdb_id=foo&kvdb_id=bar).

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {
        'policy_type': type_,
        'ids': kvdb_id if kvdb_id else None
    }

    dapi = DistributedAPI(
        f=kvdb.delete_kvdbs,
        f_kwargs=remove_nones_to_dict(f_kwargs),
        request_type='local_master',
        is_async=True,
        wait_for_complete=wait_for_complete,
        logger=logger,
        rbac_permissions=request.context['token_info']['rbac_policies']
    )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
