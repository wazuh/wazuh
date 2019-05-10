# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging

from connexion.lifecycle import ConnexionResponse

from api.models.base_model_ import Data
from api.util import remove_nones_to_dict, exception_handler, parse_api_param, raise_if_exc
from wazuh.cluster.dapi.dapi import DistributedAPI
from wazuh.decoder import Decoder

loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
def get_decoders(pretty: bool = False, wait_for_complete: bool = False, offset: int = 0, limit: int = None,
                 sort: str = None, search: str = None, file: str = None, path: str = None,
                 status: str = None):
    """Get all decoders

    Returns information about all decoders included in ossec.conf. This information include decoder's route,
    decoder's name, decoder's file among others

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
                 ascending or descending order.
    :param search: Looks for elements with the specified string
    :param file: Filters by filename.
    :param path: Filters by path
    :param status: Filters by list status.
    """
    f_kwargs = {'offset': offset, 'limit': limit, 'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'), 'status': status, 'file': file, 'path': path}

    dapi = DistributedAPI(f=Decoder.get_decoders,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_decoders_by_name(pretty: bool = False, wait_for_complete: bool = False, offset: int = 0, limit: int = None,
                         sort: str = None, search: str = None, decoder_name = None):
    """Get decoders by name

    Returns information about decoders with a specified name. This information include decoder's route, decoder's name,
    decoder's file among others.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
                 ascending or descending order.
    :param search: Looks for elements with the specified string
    :param decoder_name: Decoder name.
    """
    f_kwargs = {'offset': offset, 'limit': limit, 'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'), 'name': decoder_name}

    dapi = DistributedAPI(f=Decoder.get_decoders,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_decoders_files(pretty: bool = False, wait_for_complete: bool = False, offset: int = 0, limit: int = None,
                       sort: str = None, search: str = None, file: str = None, path: str = None,
                       status: str = None):
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
    :param file: Filters by filename.
    :param path: Filters by path
    :param status: Filters by list status.
    """
    f_kwargs = {'offset': offset, 'limit': limit, 'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'), 'file': file, 'path': path, 'status': status}

    dapi = DistributedAPI(f=Decoder.get_decoders_files,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def get_download_file(pretty: bool = False, wait_for_complete: bool = False, file: str = None):
    """Download an specified decoder file.

    Download an specified decoder file.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param file: File name to download.
    :return:
    """
    f_kwargs = {'file': file}

    dapi = DistributedAPI(f=Decoder.get_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = ConnexionResponse(body=data["message"], mimetype='application/xml')
    return response


@exception_handler
def get_decoders_parents(pretty: bool = False, wait_for_complete: bool = False, offset: int = 0, limit: int = None,
                         sort: str = None, search: str = None):
    """Get decoders by parents

    Returns information about all parent decoders. A parent decoder is a decoder used as base of other decoders

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
                 ascending or descending order.
    :param search: Looks for elements with the specified string
    """
    f_kwargs = {'offset': offset, 'limit': limit, 'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'), 'parents': True}

    dapi = DistributedAPI(f=Decoder.get_decoders,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200
