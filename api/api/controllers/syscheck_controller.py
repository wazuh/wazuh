# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging

import connexion
import dateutil.parser

import wazuh.syscheck as syscheck
from api.models.base_model_ import Data
from api.util import remove_nones_to_dict, exception_handler, parse_api_param, raise_if_exc
from wazuh.cluster.dapi.dapi import DistributedAPI

loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
def put_syscheck(pretty=False, wait_for_complete=False):
    """

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    """
    f_kwargs = {'all_agents': True}

    dapi = DistributedAPI(f=syscheck.run,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_syscheck_agent(agent_id, pretty=False, wait_for_complete=False, offset=0, 
                       limit=None, select=None, sort=None, search=None,
                       summary=False, md5=None, sha1=None, sha256=None):
    """
    :param agent_id: Agent ID
    :type agent_id: str
    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param select: Select which fields to return (separated by comma)
    :type select: List[str]
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order. 
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param summary: Returns a summary grouping by filename.
    :type summary: bool
    :param md5: Filters files with the specified MD5 checksum.
    :type md5: str
    :param sha1: Filters files with the specified SHA1 checksum.
    :type sha1: str
    :param sha256: Filters files with the specified SHA256 checksum.
    :type sha256: str
    """

    # get type parameter from query
    type_ = connexion.request.args.get('type', None)
    # get hash parameter from query
    hash_ = connexion.request.args.get('hash', None)
    # get file parameter from query
    file_ = connexion.request.args.get('file', None)

    filters = {'type': type_, 'md5': md5, 'sha1': sha1,
               'sha256': sha256, 'hash': hash_, 'file': file_}

    f_kwargs = {'agent_id': agent_id, 'offset': offset, 'limit': limit,
                'select': select, 'sort': parse_api_param(sort, 'sort'), 'search': parse_api_param(search, 'search'),
                'summary': summary, 'filters': filters}

    dapi = DistributedAPI(f=syscheck.files,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    return response, 200


@exception_handler
def put_syscheck_agent(agent_id, pretty=False, wait_for_complete=False):
    """

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
    """
    f_kwargs = {'agent_id': agent_id}

    dapi = DistributedAPI(f=syscheck.run,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def delete_syscheck_agent(agent_id, pretty=False, wait_for_complete=False):
    """

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
    """
    f_kwargs = {'agent_id': agent_id}

    dapi = DistributedAPI(f=syscheck.clear,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    return data, 200


@exception_handler
def get_last_scan_agent(agent_id, pretty=False, wait_for_complete=False):
    """

    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param agent_id: Agent ID
    :type agent_id: str
    """
    f_kwargs = {'agent_id': agent_id}

    dapi = DistributedAPI(f=syscheck.last_scan,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='distributed_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    # Check if scan is running to set end to None
    if data["start"] is not None:
        start = data["start"]
        end = data["end"]
        if end is not None and start > end:
            data["end"] = None

    response = Data(data)

    return response, 200
