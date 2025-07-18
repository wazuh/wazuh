# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from typing import Union

from connexion import request
from connexion.lifecycle import ConnexionResponse

from api.controllers.util import json_response, XML_CONTENT_TYPE
from api.models.base_model_ import Body
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh import decoder as decoder_framework
from wazuh.core.cluster.control import get_system_nodes_or_none
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.results import AffectedItemsWazuhResult

logger = logging.getLogger('wazuh-api')


async def get_decoders(decoder_names: list = None, pretty: bool = False, wait_for_complete: bool = False,
                       offset: int = 0, limit: int = None, select: list = None, sort: str = None, search: str = None,
                       q: str = None, filename: str = None, relative_dirname: str = None,
                       status: str = None, distinct: bool = False) -> ConnexionResponse:
    """Get all decoders.

    Returns information about all the decoders included in the ossec.conf file.
    This information includes the decoders' routes, decoders' names, decoders' files, etc.

    Parameters
    ----------
    decoder_names : list
        Filters by decoder name.
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    search : str
        Look for elements with the specified string.
    q : str
        Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;active&amp;quot;
    filename : str
        List of filenames to filter by.
    relative_dirname : str
        Filters by relative dirname.
    status : str
        Filters by status.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'names': decoder_names,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['filename', 'position'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'q': q,
                'filename': filename,
                'status': status,
                'relative_dirname': relative_dirname,
                'distinct': distinct}

    dapi = DistributedAPI(f=decoder_framework.get_decoders,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_decoders_files(pretty: bool = False, wait_for_complete: bool = False, offset: int = 0,
                             limit: int = None, sort: str = None, search: str = None, filename: str = None,
                             relative_dirname: str = None, status: str = None, q: str = None,
                             select: str = None, distinct: bool = False) -> ConnexionResponse:
    """Get all decoders' files.

    Returns information about all decoders' files used in Wazuh.
    This information includes the decoders' file, decoders' routes, decoders' statuses, etc.

    Parameters
    ----------
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    search : str
        Look for elements with the specified string.
    filename : str
        List of filenames to filter by.
    relative_dirname : str
        Filters by relative dirname.
    status : str
        Filters by status.
    q : str
        Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;active&amp;quot;
    select : str
        Select which fields to return (separated by comma).
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['filename'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'filename': filename,
                'relative_dirname': relative_dirname,
                'status': status,
                'q': q,
                'select': select,
                'distinct': distinct}

    dapi = DistributedAPI(f=decoder_framework.get_decoders_files,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_decoders_parents(pretty: bool = False, wait_for_complete: bool = False, offset: int = 0,
                               limit: int = None, select: list = None, sort: str = None,
                               search: str = None) -> ConnexionResponse:
    """Get decoders by parents.

    Returns information about all parent decoders. A parent decoder is a decoder used as base of other decoders.

    Parameters
    ----------
    pretty: bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    search : str
        Look for elements with the specified string.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'select': select,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['filename', 'position'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'parents': True}

    dapi = DistributedAPI(f=decoder_framework.get_decoders,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_file(pretty: bool = False, wait_for_complete: bool = False, 
                   filename: str = None, relative_dirname: str = None, 
                   raw: bool = False) -> ConnexionResponse:
    """Get decoder file content.

    Parameters
    ----------
    pretty : bool
        Show results in human-readable format. It only works when `raw` is False (JSON format).
    wait_for_complete : bool
        Disable response timeout or not.
    filename : str
        Filename to download.
    raw : bool
        Whether to return the file content in raw or JSON format.
     relative_dirname : str
        Relative directory where the decoder is located. Default None.

    Returns
    -------
    web.json_response or ConnexionResponse
        Depending on the `raw` parameter, it will return a ConnexionResponse object:
            raw=True            -> ConnexionResponse (application/xml)
            raw=False (default) -> ConnexionResponse (application/json)
        If any exception was raised, it will return a ConnexionResponse with details.
    """
    f_kwargs = {'filename': filename, 'raw': raw, 'relative_dirname': relative_dirname}

    dapi = DistributedAPI(f=decoder_framework.get_decoder_file,
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
                                     content_type=XML_CONTENT_TYPE)

    return response


async def put_file(body: bytes, filename: str = None, relative_dirname: str = None,
                   overwrite: bool = False, pretty: bool = False,
                   wait_for_complete: bool = False) -> ConnexionResponse:
    """Upload a decoder file.

    Parameters
    ----------
    body : bytes
        Body request with the file content to be uploaded.
    filename : str
        Name of the file.
    relative_dirname : str
        Relative directory where the decoder is located.
    overwrite : bool
        If set to false, an exception will be raised when  
        updating contents of an already existing file.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

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
                'content': parsed_body,
                'relative_dirname': relative_dirname}

    nodes = await get_system_nodes_or_none()

    dapi = DistributedAPI(f=decoder_framework.upload_decoder_file,
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


async def delete_file(filename: str = None, relative_dirname: str = None,
                      pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Delete a decoder file.

    Parameters
    ----------
    filename : str
        Name of the file.
    relative_dirname : str
        Relative directory where the decoder is located.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'filename': filename, 'relative_dirname': relative_dirname}

    nodes = await get_system_nodes_or_none()

    dapi = DistributedAPI(f=decoder_framework.delete_decoder_file,
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
