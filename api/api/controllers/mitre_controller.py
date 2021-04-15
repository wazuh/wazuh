# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from aiohttp import web

from api.encoder import dumps, prettify
from api.util import raise_if_exc, parse_api_param, remove_nones_to_dict
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh import mitre

logger = logging.getLogger('wazuh-api')


async def get_metadata(request, pretty=False, wait_for_complete=False):
    """Return the metadata of the MITRE's database

    Parameters
    ----------
    pretty : bool, optional
        Show results in human-readable format
    wait_for_complete : bool, optional
        Disable timeout response

    Returns
    -------
    Metadata of MITRE's db
    """

    dapi = DistributedAPI(f=mitre.mitre_metadata,
                          f_kwargs={},
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_tactics():
    """TODO
    """
    # TODO


async def get_techniques(request, technique_ids=None, pretty=False, wait_for_complete=False, offset=None,
                         limit=None, sort=None, search=None, select=None, q=None):
    """Get information of specified MITRE's techniques.

    Parameters
    ----------
    request : connexion.request
    technique_ids : list, optional
        List of technique ids to be obtained
    pretty : bool, optional
        Show results in human-readable format
    wait_for_complete : bool, optional
        Disable timeout response
    offset : int, optional
        First item to return
    limit : int, optional
        Maximum number of items to return
    search : str
        Looks for elements with the specified string
    select : list[str]
        Select which fields to return (separated by comma).
    sort : str, optional
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order
    q : str
        Query to filter by.

    Returns
    -------
    MITRE's techniques information
    """
    f_kwargs = {'filters': {
        'id': technique_ids,
    },
        'offset': offset,
        'limit': limit,
        'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else None,
        'sort_ascending': False if sort is None or parse_api_param(sort, 'sort')['order'] == 'desc' else True,
        'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
        'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
        'select': select, 'q': q}

    dapi = DistributedAPI(f=mitre.mitre_techniques,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_mitigations():
    """TODO
    """
    # TODO


async def get_groups():
    """TODO
    """
    # TODO


async def get_software():
    """TODO
    """
    # TODO
