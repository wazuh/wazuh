# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from aiohttp import web
from connexion.lifecycle import ConnexionResponse

from api.encoder import dumps, prettify
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh import decoder as decoder_framework
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh-api')


async def get_decoders(request, decoder_names: list = None, pretty: bool = False, wait_for_complete: bool = False,
                       offset: int = 0, limit: int = None, select: list = None, sort: str = None, search: str = None,
                       q: str = None, filename: str = None, relative_dirname: str = None, status: str = None):
    """Get all decoders

    Returns information about all decoders included in ossec.conf. This information include decoder's route,
    decoder's name, decoder's file among others

    :param decoder_names: Filters by decoder name.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: List of selected fields to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param q: Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;active&amp;quot;
    :param filename: List of filenames to filter by.
    :param relative_dirname: Filters by relative dirname.
    :param status: Filters by list status.
    :return: Data object
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
                'relative_dirname': relative_dirname}

    dapi = DistributedAPI(f=decoder_framework.get_decoders,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_decoders_files(request, pretty: bool = False, wait_for_complete: bool = False, offset: int = 0,
                             limit: int = None, sort: str = None, search: str = None, filename: str = None,
                             relative_dirname: str = None, status: str = None):
    """Get all decoders files

    Returns information about all decoders files used in Wazuh. This information include decoder's file, decoder's route
    and decoder's status among others

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param filename: List of filenames to filter by.
    :param relative_dirname: Filters by relative dirname
    :param status: Filters by list status
    :return: Data object
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['filename'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'filename': filename,
                'relative_dirname': relative_dirname,
                'status': status}

    dapi = DistributedAPI(f=decoder_framework.get_decoders_files,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def get_download_file(request, pretty: bool = False, wait_for_complete: bool = False, filename: str = None):
    """Download an specified decoder file.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param filename: Filename to download.
    :return: Raw xml file
    """
    f_kwargs = {'filename': filename}

    dapi = DistributedAPI(f=decoder_framework.get_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())
    response = ConnexionResponse(body=data["message"], mimetype='application/xml')

    return response


async def get_decoders_parents(request, pretty: bool = False, wait_for_complete: bool = False, offset: int = 0,
                               limit: int = None, select : list = None, sort: str = None, search: str = None):
    """Get decoders by parents

    Returns information about all parent decoders. A parent decoder is a decoder used as base of other decoders

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param select: List of selected fields to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :return: Data object
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
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
