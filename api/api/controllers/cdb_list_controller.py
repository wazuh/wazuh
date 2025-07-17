# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from connexion import request
from connexion.lifecycle import ConnexionResponse

from api.controllers.util import json_response
from api.models.base_model_ import Body
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh import cdb_list
from wazuh.core.cluster.control import get_system_nodes
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.results import AffectedItemsWazuhResult

logger = logging.getLogger('wazuh-api')


async def get_lists(pretty: bool = False, wait_for_complete: bool = False, offset: int = 0, limit: int = None,
                    select: list = None, sort: str = None, search: str = None, filename: str = None,
                    relative_dirname: str = None, q: str = None, distinct: bool = False) -> ConnexionResponse:
    """Get all CDB lists.

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
    filename : str
        Filenames to filter by (separated by comma).
    relative_dirname : str
        Filter by relative dirname.
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
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['relative_dirname',
                                                                                             'filename'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'filename': filename,
                'relative_dirname': relative_dirname,
                'q': q,
                'distinct': distinct
                }

    dapi = DistributedAPI(f=cdb_list.get_lists,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_file(pretty: bool = False, wait_for_complete: bool = False, filename: str = None,
                   raw: bool = False) -> ConnexionResponse:
    """Get content of one CDB list file, in raw or dict format.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    filename : str
        Name of filename to get data from.
    raw : bool, optional
        Respond in raw format.

    Returns
    -------
    ConnexionResponse
        Depending on the `raw` parameter, it will return a ConnexionResponse object:
            raw=True            -> ConnexionResponse (text/plain)
            raw=False (default) -> ConnexionResponse (application/json)
        If any exception was raised, it will return a ConnexionResponse with details.
    """
    f_kwargs = {'filename': filename, 'raw': raw}

    dapi = DistributedAPI(f=cdb_list.get_list_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())
    if isinstance(data, AffectedItemsWazuhResult):
        response = json_response(data, pretty=pretty)
    else:
        response = ConnexionResponse(body=data["message"],
                                     content_type='text/plain; charset=utf-8')

    return response


async def put_file(body: bytes, overwrite: bool = False, pretty: bool = False, wait_for_complete: bool = False,
                   filename: str = None) -> ConnexionResponse:
    """Upload content of CDB list file.

    Parameters
    ----------
    body : bytes
        Bytes object with the content of the file to be uploaded.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    overwrite : bool
        If set to false, an exception will be raised when updating contents of an already existing filename.
    filename : str
        Name of the new CDB list file.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    # Parse body to utf-8
    Body.validate_content_type(request, expected_content_type='application/octet-stream')
    parsed_body = Body.decode_body(body, unicode_error=1911, attribute_error=1912)

    f_kwargs = {'filename': filename,
                'overwrite': overwrite,
                'content': parsed_body}

    nodes = await get_system_nodes()
    if isinstance(nodes, Exception):
        nodes = None

    dapi = DistributedAPI(f=cdb_list.upload_list_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          broadcasting=True,
                          nodes=nodes
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def delete_file(pretty: bool = False, wait_for_complete: bool = False,
                      filename: str = None) -> ConnexionResponse:
    """Delete a CDB list file.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    filename : str
        Name of the CDB list file to delete.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'filename': filename}

    nodes = await get_system_nodes()
    if isinstance(nodes, Exception):
        nodes = None

    dapi = DistributedAPI(f=cdb_list.delete_list_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies'],
                          broadcasting=True,
                          nodes=nodes
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_lists_files(pretty: bool = False, wait_for_complete: bool = False, offset: int = 0,
                          limit: int = None, sort: str = None, search: str = None, filename: str = None,
                          relative_dirname: str = None) -> ConnexionResponse:
    """Get paths from all CDB lists.

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
    sort : str
        Sort the collection by a field or fields (separated by comma). Use +/- at the beginning
        to list in ascending or descending order.
    search : str
        Look for elements with the specified string.
    filename : str
        Filenames to filter by (separated by comma).
    relative_dirname : str
        Filter by relative dirname.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['relative_dirname',
                                                                                             'filename'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'search_in_fields': ['filename', 'relative_dirname'],
                'filename': filename,
                'relative_dirname': relative_dirname,
                }

    dapi = DistributedAPI(f=cdb_list.get_path_lists,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
