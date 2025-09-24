# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from connexion import request
from connexion.lifecycle import ConnexionResponse

from api.controllers.util import json_response
from api.models.base_model_ import Body
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh import decoder as decoder_framework
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh-api')


async def get_decoder(decoders_list: list = None, pretty: bool = False, wait_for_complete: bool = False,
                       offset: int = 0, limit: int = None, select: list = None, sort: str = None,
                       search: str = None, q: str = None, status: str = None, distinct: bool = False,
                       type: str = None) -> ConnexionResponse:
    """Get all decoders.

    Returns information about all the decoders included in the ossec.conf file.
    This information includes the decoders' routes, decoders' names, decoders' files, etc.

    Parameters
    ----------
    decoders_list : list
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
    status : str
        Filters by status.
    distinct : bool
        Look for distinct values.
    type: str
        Policy type
    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'names': decoders_list,
                'offset': offset,
                'limit': limit,
                'select': select,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['filename', 'position'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'q': q,
                'status': status,
                'distinct': distinct,
                'policy_type': type}

    dapi = DistributedAPI(f=decoder_framework.get_decoder,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def create_decoder(body: bytes, pretty: bool = False, wait_for_complete: bool = False,
                         type: str = None) -> ConnexionResponse:
    """Create a decoder file.

    Parameters
    ----------
    body : bytes
        Body request with the file content to be uploaded.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    type: str
        Policy type

    Returns
    -------
    ConnexionResponse
        API response.
    """
    # Parse body to utf-8
    Body.validate_content_type(request, expected_content_type='application/octet-stream')
    parsed_body = Body.decode_body(body, unicode_error=1911, attribute_error=1912)

    f_kwargs = {'content': parsed_body,
                'policy_type': type}

    dapi = DistributedAPI(f=decoder_framework.create_decoder,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def update_decoder(body: bytes, pretty: bool = False, wait_for_complete: bool = False,
                         type: str = None) -> ConnexionResponse:
    """Upload a decoder file.

    Parameters
    ----------
    body : bytes
        Body request with the file content to be uploaded.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    type: str
        Policy type

    Returns
    -------
    ConnexionResponse
        API response.
    """
    # Parse body to utf-8
    Body.validate_content_type(request, expected_content_type='application/octet-stream')
    parsed_body = Body.decode_body(body, unicode_error=1911, attribute_error=1912)

    f_kwargs = {'content': parsed_body,
                'policy_type': type}

    dapi = DistributedAPI(f=decoder_framework.update_decoder,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def delete_decoder(decoders_list: list = None, pretty: bool = False, wait_for_complete: bool = False,
                         type: str = None) -> ConnexionResponse:
    """Delete a decoder file.

    Parameters
    ----------
    decoders_list : list
        Filters by decoder name.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    type: str
        Policy type

    Returns
    -------
    ConnexionResponse
        API response.
    """
    f_kwargs = {'names': decoders_list,
                'policy_type': type}

    dapi = DistributedAPI(f=decoder_framework.delete_decoder,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=True,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
