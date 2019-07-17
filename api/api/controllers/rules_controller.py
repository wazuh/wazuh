# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import logging

import connexion

from api.models.base_model_ import Data
from api.util import remove_nones_to_dict, exception_handler, parse_api_param, raise_if_exc, flask_cached
from wazuh.cluster.dapi.dapi import DistributedAPI
from wazuh.exception import WazuhError
from wazuh.rule import Rule

loop = asyncio.get_event_loop()
logger = logging.getLogger('wazuh')


@exception_handler
@flask_cached
def get_rules(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None, search=None, status=None,
              group=None, level=None, file=None, path=None, pci=None, gdpr=None, gpg13=None, hipaa=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param sort: Sorts the collection by a field or fields (separated by comma).
    Use +/- at the beginning to list in ascending or descending order.
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
    :param gpg13: Filters by GPG13 requirement.
    :type gpg13: str
    :param hipaa: Filters by HIPAA requirement.
    :type hipaa: str
    :param nist-800-53: Filters by nist-800-53 requirement.
    :type nist-800-53: str
    """

    # We access nist-800-53 from connexion request since it is set with an invalid variable name
    try:
        nist_800_53 = connexion.request.args['nist-800-53']
    except KeyError:
        nist_800_53 = None

    f_kwargs = {'offset': offset, 'limit': limit, 'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'), 'status': status, 'group': group, 'level': level,
                'file': file, 'path': path, 'pci': pci, 'gdpr': gdpr, 'gpg13': gpg13, 'hipaa': hipaa,
                'nist_800_53': nist_800_53}

    dapi = DistributedAPI(f=Rule.get_rules,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))

    # Get rules objects as dict
    rules_list = []
    for rule in data['items']:
        rule = rule.to_dict()
        rules_list.append(rule)

    data['items'] = rules_list
    response = Data(data)

    return response, 200


@exception_handler
@flask_cached
def get_rules_groups(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None, search=None):
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
    f_kwargs = {'offset': offset, 'limit': limit, 'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search')}

    dapi = DistributedAPI(f=Rule.get_groups,
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
@flask_cached
def get_rules_pci(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None, search=None):
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
    f_kwargs = {'offset': offset, 'limit': limit, 'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search')}

    dapi = DistributedAPI(f=Rule.get_pci,
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
@flask_cached
def get_rules_gdpr(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None, search=None):
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
    f_kwargs = {'offset': offset, 'limit': limit, 'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search')}

    dapi = DistributedAPI(f=Rule.get_gdpr,
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
@flask_cached
def get_rules_gpg13(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None, search=None):
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
    f_kwargs = {'offset': offset, 'limit': limit, 'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search')}

    dapi = DistributedAPI(f=Rule.get_gpg13,
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
@flask_cached
def get_rules_hipaa(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None, search=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param sort: Sorts the collection by a field or fields (separated by comma).
    Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    """
    f_kwargs = {'offset': offset, 'limit': limit, 'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search')}

    dapi = DistributedAPI(f=Rule.get_hipaa,
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
@flask_cached
def get_rules_nist_800_53(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None, search=None):
    """
    :param pretty: Show results in human-readable format
    :type pretty: bool
    :param wait_for_complete: Disable timeout response
    :type wait_for_complete: bool
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param sort: Sorts the collection by a field or fields (separated by comma).
    Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    """
    f_kwargs = {'offset': offset, 'limit': limit, 'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search')}

    dapi = DistributedAPI(f=Rule.get_nist_800_53,
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
@flask_cached
def get_rules_files(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None, search=None,
                    status=None, file=None, path=None):
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
    """
    f_kwargs = {'offset': offset, 'limit': limit, 'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search'), 'status': status, 'file': file,
                'path': path}

    dapi = DistributedAPI(f=Rule.get_rules_files,
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
@flask_cached
def get_download_file(pretty: bool = False, wait_for_complete: bool = False, file: str = None):
    """Download an specified decoder file.
    Download an specified decoder file.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param file: File name to download.
    :return:
    """
    f_kwargs = {'filename': file}

    dapi = DistributedAPI(f=Rule.get_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = connexion.lifecycle.ConnexionResponse(body=data["message"], mimetype='application/xml')
    return response


@exception_handler
@flask_cached
def get_rules_id(pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None, search=None, rule_id=None):
    """
    :param pretty: Show results in human-readable format 
    :type pretty: bool
    :param wait_for_complete: Disable timeout response 
    :type wait_for_complete: bool
    :param offset: First element to return in the collection
    :type offset: int
    :param limit: Maximum number of elements to return
    :type limit: int
    :param sort: Sorts the collection by a field or fields (separated by comma).
    Use +/- at the beginning to list in ascending or descending order.
    :type sort: str
    :param search: Looks for elements with the specified string
    :type search: str
    :param rule_id: Filters by rule ID
    :type rule_id: str
    """
    f_kwargs = {'id': rule_id, 'offset': offset, 'limit': limit, 'sort': parse_api_param(sort, 'sort'),
                'search': parse_api_param(search, 'search')}

    dapi = DistributedAPI(f=Rule.get_rules,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          pretty=pretty,
                          logger=logger
                          )
    data = raise_if_exc(loop.run_until_complete(dapi.distribute_function()))
    response = Data(data)

    if response.data['totalItems'] == 1:
        response.data = {'items': [response.data['items'][0].to_dict()], 'totalItems': response.data['totalItems']}
    elif response.data['totalItems'] > 1 or response.data['totalItems'] < 0:
        raise WazuhError(1206)

    return response, 200
