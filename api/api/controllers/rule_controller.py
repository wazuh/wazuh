# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from typing import Union

from aiohttp import web
from aiohttp_cache import cache
from connexion.lifecycle import ConnexionResponse

from api.configuration import api_conf
from api.encoder import dumps, prettify
from api.models.base_model_ import Body
from api.util import remove_nones_to_dict, parse_api_param, raise_if_exc
from wazuh import rule as rule_framework
from wazuh.core.cluster.dapi.dapi import DistributedAPI
from wazuh.core.results import AffectedItemsWazuhResult

logger = logging.getLogger('wazuh-api')


@cache(expires=api_conf['cache']['time'])
async def get_rules(request, rule_ids: list = None, pretty: bool = False, wait_for_complete: bool = False,
                    offset: int = 0, select: str = None, limit: int = None, sort: str = None, search: str = None,
                    q: str = None, status: str = None, group: str = None, level: str = None, filename: list = None,
                    relative_dirname: str = None, pci_dss: str = None, gdpr: str = None, gpg13: str = None,
                    hipaa: str = None, tsc: str = None, mitre: str = None, distinct: bool = False) -> web.Response:
    """Get information about all Wazuh rules.

    Parameters
    ----------
    request : connexion.request
    rule_ids : list
        Filters by rule ID.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
    search : str
        Looks for elements with the specified string.
    select : str
        Select which fields to return (separated by comma).
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    q : str
        Query to filter results by. For example q&#x3D;&amp;quot;status&#x3D;active&amp;quot;
    status : str
        Filters by rules status.
    group : str
        Filters by rule group.
    level : str
        Filters by rule level. Can be a single level (4) or an interval (2-4).
    filename : list
        List of filenames to filter by.
    relative_dirname : str
        Filters by relative dirname.
    pci_dss : str
        Filters by PCI_DSS requirement name.
    gdpr : str
        Filters by GDPR requirement.
    gpg13 : str
        Filters by GPG13 requirement.
    hipaa : str
        Filters by HIPAA requirement.
    tsc : str
        Filters by TSC requirement.
    mitre : str
        Filters by mitre technique ID.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    web.Response
        API response.
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
                'mitre': mitre,
                'distinct': distinct}

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
async def get_rules_groups(request, pretty: bool = False, wait_for_complete: bool = False, offset: int = 0,
                           limit: int = None, sort: str = None, search: str = None) -> web.Response:
    """Get all rule groups names.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
    search : str
        Looks for elements with the specified string.
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.

    Returns
    -------
    web.Response
        API response.
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
async def get_rules_requirement(request, requirement: str = None, pretty: bool = False, wait_for_complete: bool = False,
                                offset: int = 0, limit: int = None, sort: str = None,
                                search: str = None) -> web.Response:
    """Get all specified requirements.

    Parameters
    ----------
    request : connexion.request
    requirement : str
        Get the specified requirement in all rules in the system.
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
    search : str
        Looks for elements with the specified string.
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.

    Returns
    -------
    web.Response
        API response.
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
async def get_rules_files(request, pretty: bool = False, wait_for_complete: bool = False, offset: int = 0,
                          limit: int = None, sort: str = None, search: str = None, status: str = None,
                          filename: list = None, relative_dirname: str = None, q: str = None,
                          select: str = None, distinct: bool = False) -> web.Response:
    """Get all the rules files.

    Parameters
    ----------
    request : connexion.request
    pretty : bool
        Show results in human-readable format.
    wait_for_complete : bool
        Disable timeout response.
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
    search : str
        Looks for elements with the specified string.
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    status : str
        Filters by rules status.
    filename : list
        List of filenames to filter by.
    relative_dirname : str
        Filters by relative dirname.
    q : str
        Query to filter results by.
    select : str
        Select which fields to return (separated by comma).
    distinct : bool
        Look for distinct values.

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'offset': offset,
                'limit': limit,
                'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else ['filename'],
                'sort_ascending': True if sort is None or parse_api_param(sort, 'sort')['order'] == 'asc' else False,
                'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
                'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
                'status': status,
                'filename': filename,
                'relative_dirname': relative_dirname,
                'q': q,
                'select': select,
                'distinct': distinct}

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
async def get_file(request, pretty: bool = False, wait_for_complete: bool = False, 
                   filename: str = None, relative_dirname: str = None, 
                   raw: bool = False) -> Union[web.Response, ConnexionResponse]:
    """Get rule file content.

    Parameters
    ----------
    request : connexion.request
    pretty : bool, optional
        Show results in human-readable format. It only works when `raw` is False (JSON format). Default `True`.
    wait_for_complete : bool, optional
        Disable response timeout or not. Default `False`.
    filename : str
        Filename to download.
    raw : bool, optional
        Whether to return the file content in raw or JSON format. Default `False`.
    relative_dirname : str
        Relative directory where the rule is located.

    Returns
    -------
    web.Response or ConnexionResponse
        Depending on the `raw` parameter, it will return a web.Response object or a ConnexionResponse object:
            raw=True            -> ConnexionResponse (application/xml)
            raw=False (default) -> web.Response      (application/json)
        If any exception was raised, it will return a web.Response with details.
    """
    f_kwargs = {'filename': filename, 'raw': raw, 'relative_dirname': relative_dirname}

    dapi = DistributedAPI(f=rule_framework.get_rule_file,
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
        response = ConnexionResponse(body=data["message"], mimetype='application/xml', content_type='application/xml')

    return response


async def put_file(request, body: dict, filename: str = None, overwrite: bool = False,
                   pretty: bool = False, relative_dirname: str = None,
                   wait_for_complete: bool = False) -> web.Response:
    """Upload a rule file.
    
    Parameters
    ----------
    request : connexion.request
    body : dict
        Body request with the file content to be uploaded.
    filename : str, optional
        Name of the file.
    overwrite : bool, optional
        If set to false, an exception will be raised when updating 
        contents of an already existing file. Default `False`
    pretty : bool, optional
        Show results in human-readable format. Default `False`
    relative_dirname : str
        Relative directory where the rule is located.
    wait_for_complete : bool, optional
        Disable timeout response. Default `False`

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
                'relative_dirname': relative_dirname,
                'content': parsed_body}

    dapi = DistributedAPI(f=rule_framework.upload_rule_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)


async def delete_file(request, filename: str = None, 
                      relative_dirname: str = None, 
                      pretty: bool = False,
                      wait_for_complete: bool = False) -> web.Response:
    """Delete a rule file.

    Parameters
    ----------
    request : connexion.request
    filename : str, optional
        Name of the file.
    relative_dirname : str
        Relative directory where the rule file is located.
    pretty : bool, optional
        Show results in human-readable format. Default `False`
    wait_for_complete : bool, optional
        Disable timeout response. Default `False`

    Returns
    -------
    web.Response
        API response.
    """
    f_kwargs = {'filename': filename, 'relative_dirname': relative_dirname}

    dapi = DistributedAPI(f=rule_framework.delete_rule_file,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_master',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return web.json_response(data=data, status=200, dumps=prettify if pretty else dumps)
