# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from aiohttp import web
from aiohttp_cache import cache
from connexion.lifecycle import ConnexionResponse

from api.configuration import api_conf
from api.encoder import dumps, prettify
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh import rule as rule_framework
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh')


@cache(expires=api_conf['cache']['time'])
async def get_rules(request, rule_ids=None, pretty=False, wait_for_complete=False, offset=0, select=None,
                    limit=None, sort=None, search=None, q=None, status=None, group=None, level=None, filename=None,
                    relative_dirname=None, pci_dss=None, gdpr=None, gpg13=None, hipaa=None, tsc=None, mitre=None):
    """Get information about all Wazuh rules.

    :param rule_ids: Filters by rule ID
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param select: List of selected fields to return
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param q: Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;active&amp;quot;
    :param status: Filters by rules status.
    :param group: Filters by rule group.
    :param level: Filters by rule level. Can be a single level (4) or an interval (2-4)
    :param filename: List of filenames to filter by.
    :param relative_dirname: Filters by relative dirname.
    :param pci_dss: Filters by PCI_DSS requirement name.
    :param gdpr: Filters by GDPR requirement.
    :param gpg13: Filters by GPG13 requirement.
    :param hipaa: Filters by HIPAA requirement.
    :param tsc: Filters by TSC requirement.
    :param mitre: Filters by mitre attack ID.
    :return: Data object
    """
    f_kwargs = {'rule_ids': rule_ids, 'offset': offset, 'limit': limit, 'select': select,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['id'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'q': q,
                'status': status,
                'group': group,
                'level': level,
                'filename': filename,
                'relative_dirname': relative_dirname,
                'pci_dss': pci_dss,
                'gdpr': gdpr,
                'gpg13': gpg13,
                'hipaa': hipaa,
                'nist_800_53': request.query.get('nist-800-53', None),
                'tsc': tsc,
                'mitre': mitre}

    dapi = DistributedAPI(f=rule_framework.get_rules,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@cache(expires=api_conf['cache']['time'])
async def get_rules_groups(request, pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None,
                           search=None):
    """Get all rule groups names.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :return: Data object
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else [''],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                }

    dapi = DistributedAPI(f=rule_framework.get_groups,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@cache(expires=api_conf['cache']['time'])
async def get_rules_requirement(request, requirement=None, pretty=False, wait_for_complete=False, offset=0, limit=None,
                                sort=None, search=None):
    """Get all specified requirements

    :param requirement: Get the specified requirement in all rules in the system.
    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :return: Data object
    """
    f_kwargs = {'requirement': requirement.replace('-', '_'), 'offset': offset, 'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else [''],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None}

    dapi = DistributedAPI(f=rule_framework.get_requirement,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@cache(expires=api_conf['cache']['time'])
async def get_rules_files(request, pretty=False, wait_for_complete=False, offset=0, limit=None, sort=None, search=None,
                          status=None, filename=None, relative_dirname=None):
    """Get all files which defines rules

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param offset: First element to return in the collection
    :param limit: Maximum number of elements to return
    :param sort: Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
    ascending or descending order.
    :param search: Looks for elements with the specified string
    :param status: Filters by rules status.
    :param filename: List of filenames to filter by..
    :param relative_dirname: Filters by relative dirname.
    :return: Data object
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['filename'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'status': status,
                'filename': filename,
                'relative_dirname': relative_dirname}

    dapi = DistributedAPI(f=rule_framework.get_rules_files,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


@cache(expires=api_conf['cache']['time'])
async def get_download_file(request, pretty: bool = False, wait_for_complete: bool = False, filename: str = None):
    """Download an specified decoder file.

    :param pretty: Show results in human-readable format
    :param wait_for_complete: Disable timeout response
    :param filename: Filename to download.
    :return: Raw XML file
    """
    f_kwargs = {'filename': filename}

    dapi = DistributedAPI(f=rule_framework.get_file,
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
