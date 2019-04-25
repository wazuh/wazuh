# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import connexion
import logging

from api.models.list_metadata import ListMetadata
from api.models.rules_files_model import RulesFiles
from api.models.rules_model import Rules as RulesModel
from api.util import remove_nones_to_dict, exception_handler, parse_api_param
from ..util import format_data
from wazuh.cluster.dapi.dapi import DistributedAPI
from wazuh.rule import Rule
from wazuh.exception import WazuhException, WazuhError

loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
def get_rules(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None,
              search=None, list_status=None, group=None, level=None, file=None, path=None,
              pci=None, gdpr=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param status: Filters by rules status.
    :type status: List[str]
    :param group: Filters by rule group.
    :type group: str
    :param level: Filters by rule level. Can be a single level (4) or an interval (2-4)
    :type level: str
    :param file: Filters by filename.
    :type file: str
    :param path: Filters by rule path.
    :type path: str
    :param pci: Filters by PCI requirement name.
    :type pci: str
    :param gdpr: Filters by GDPR requirement.
    :type gdpr: str
    """

    if sort:
        sort = parse_api_param(sort, 'sort')

    if search:
        search = parse_api_param(search, 'search')

    f_kwargs = {'offset': offset, 'limit': limit, 'sort': sort,
                'search': search, 'status': list_status, 'group': group,
                'level': level, 'file': file, 'path': path,
                'pci': pci, 'gdpr': gdpr}

    dapi = DistributedAPI(f=Rule.get_rules,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = loop.run_until_complete(dapi.distribute_function())

    if isinstance(data, dict):
        # get rules as dict
        rules_list = []
        for rule in data['items']:
            rule = rule.to_dict()
            rules_list.append(rule)

        data['items'] = rules_list
        data = format_data(data)

    return data, 200


@exception_handler
def get_rules_groups(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None,
                     search=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    """

    if sort:
        sort = parse_api_param(sort, 'sort')

    if search:
        search = parse_api_param(search, 'search')

    f_kwargs = {'offset': offset, 'limit': limit, 'sort': sort,
                'search': search}

    dapi = DistributedAPI(f=Rule.get_groups,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = loop.run_until_complete(dapi.distribute_function())
    data = format_data(data)

    return data, 200


@exception_handler
def get_rules_pci(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None,
                  search=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    """

    if sort:
        sort = parse_api_param(sort, 'sort')

    if search:
        search = parse_api_param(search, 'search')

    f_kwargs = {'offset': offset, 'limit': limit, 'sort': sort,
                'search': search}

    dapi = DistributedAPI(f=Rule.get_pci,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = loop.run_until_complete(dapi.distribute_function())
    data = format_data(data)

    return data, 200


@exception_handler
def get_rules_gdpr(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None,
                   search=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    """

    if sort:
        sort = parse_api_param(sort, 'sort')

    if search:
        search = parse_api_param(search, 'search')

    f_kwargs = {'offset': offset, 'limit': limit, 'sort': sort,
                'search': search}

    dapi = DistributedAPI(f=Rule.get_gdpr,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = loop.run_until_complete(dapi.distribute_function())
    data = format_data(data)

    return data, 200


@exception_handler
def get_rules_files(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None,
                    search=None, status=None, file=None, path=None, download=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param status: Filters by rules status.
    :type status: List[str]
    :param file: Filters by filename.
    :type file: str
    :param path: Filters by rule path.
    :type path: str
    :param download: Download the specified file.
    :type download: str
    """

    if sort:
        sort = parse_api_param(sort, 'sort')

    if search:
        search = parse_api_param(search, 'search')

    f_kwargs = {'offset': offset, 'limit': limit, 'sort': sort,
                'search': search, 'status': status, 'file': file,
                'path': path, 'download': download}

    dapi = DistributedAPI(f=Rule.get_rules_files,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = loop.run_until_complete(dapi.distribute_function())
    data = format_data(data)

    return data, 200


@exception_handler
def get_rules_id(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None, 
                 search=None, rule_id=None):
    """
    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in ascending or descending order. 
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param rule_id: Filters by rule ID
    :type rule_id: str
    """

    if sort:
        sort = parse_api_param(sort, 'sort')

    if search:
        search = parse_api_param(search, 'search')

    f_kwargs = {'id': rule_id, 'offset': offset, 'limit': limit, 'sort': sort,
                'search': search}

    dapi = DistributedAPI(f=Rule.get_rules,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = loop.run_until_complete(dapi.distribute_function())
    data = format_data(data)

    if isinstance(data, WazuhError):
        return data, 200

    if data['data']['totalItems'] == 1:
        data['data'] = {'items': data['data']['items'][0].to_dict(), 'totalItems': data['data']['totalItems']}
    elif data['data']['totalItems'] > 1 or data['data']['totalItems'] < 0:
        raise WazuhError(1206)

    return data, 200
