# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from typing import Union

from aiohttp import web
from connexion.lifecycle import ConnexionResponse

from api.encoder import dumps, prettify
from api.models.base_model_ import Body
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh import cdb_list
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.results import AffectedItemsWazuhResult

logger = logging.getLogger('wazuh-api')


async def get_lists(request, pretty: bool = False, wait_for_complete: bool = False, offset: int = 0, limit: int = None,
                    select: list = None, sort: str = None, search: str = None, filename: str = None,
                    relative_dirname: str = None, q: str = None, distinct: bool = False) -> web.Response:
    """Get all CDB lists.

    Parameters
    ----------
    request : connexion.request
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
    web.Response
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
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_file(request, pretty: bool = False, wait_for_complete: bool = False, filename: str = None,
                   raw: bool = False) -> Union[web.Response, ConnexionResponse]:
    """Get content of one CDB list file, in raw or dict format.

    Parameters
    ----------
    request : connexion.request
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
    web.Response or ConnexionResponse
        Depending on the `raw` parameter, it will return a web.Response object or a ConnexionResponse object:
            raw=True            -> ConnexionResponse (text/plain)
            raw=False (default) -> web.Response      (application/json)
        If any exception was raised, it will return a web.Response with details.
    """
    f_kwargs = {'filename': filename, 'raw': raw}

    dapi = DistributedAPI(f=cdb_list.get_list_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())
    if isinstance(data, AffectedItemsWazuhResult):
        response = web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
    else:
        response = ConnexionResponse(body=data["message"], mimetype='text/plain', content_type='text/plain')

    return response


async def put_file(request, body: dict, overwrite: bool = False, pretty: bool = False, wait_for_complete: bool = False,
                   filename: str = None) -> web.Response:
    """Upload content of CDB list file.

    Parameters
    ----------
    request : connexion.request
    body : dict
        Dictionary with the content of the file to be uploaded.
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
    web.Response
        API response.
    """
    # Parse body to utf-8
    Body.validate_content_type(request, expected_content_type='application/octet-stream')
    parsed_body = Body.decode_body(body, unicode_error=1911, attribute_error=1912)

    f_kwargs = {'filename': filename,
                'overwrite': overwrite,
                'content': parsed_body}

    dapi = DistributedAPI(f=cdb_list.upload_list_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def delete_file(request, pretty: bool = False, wait_for_complete: bool = False,
                      filename: str = None) -> web.Response:
    """Delete a CDB list file.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    filename : str
        Name of the CDB list file to delete.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'filename': filename}

    dapi = DistributedAPI(f=cdb_list.delete_list_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_lists_files(request, pretty: bool = False, wait_for_complete: bool = False, offset: int = 0,
                          limit: int = None, sort: str = None, search: str = None, filename: str = None,
                          relative_dirname: str = None) -> web.Response:
    """Get paths from all CDB lists.

    Parameters
    ----------
    request : connexion.request
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
    web.Response
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
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
