# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from connexion import request
from connexion.lifecycle import ConnexionResponse

from api.controllers.util import json_response
from api.util import raise_if_exc, parse_api_param, remove_nones_to_dict
from wazuh import mitre
from wazuh.core.cluster.dapi.dapi import DistributedAPI

logger = logging.getLogger('wazuh-api')


async def get_metadata(pretty: bool = False, wait_for_complete: bool = False) -> ConnexionResponse:
    """Return the metadata of the MITRE's database.

    Parameters
    ----------
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.

    Returns
    -------
    ConnexionResponse
        API response.
    """

    dapi = DistributedAPI(f=mitre.mitre_metadata,
                          f_kwargs={},
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_references(reference_ids: list = None, pretty: bool = False, wait_for_complete: bool = False,
                         offset: int = None, limit: int = None, sort: str = None, search: str = None,
                         select: list = None, q: str = None) -> ConnexionResponse:
    """Get information of specified MITRE's references.

    Parameters
    ----------
    reference_ids : list
        List of reference ids to be obtained.
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
    select : list
        Select which fields to return (separated by comma).
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    q : str
        Query to filter by.

    Returns
    -------
    ConnexionResponse
        API response with the MITRE's references information.
    """
    f_kwargs = {
        'filters': {
            'id': reference_ids,
        },
        'offset': offset,
        'limit': limit,
        'sort_by': parse_api_param(sort, 'sort')['fields'] if sort else None,
        'sort_ascending': False if not sort or parse_api_param(sort, 'sort')['order'] == 'desc' else True,
        'search_text': parse_api_param(search, 'search')['value'] if search else None,
        'complementary_search': parse_api_param(search, 'search')['negation'] if search else None,
        'select': select,
        'q': q
    }

    dapi = DistributedAPI(f=mitre.mitre_references,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_tactics(tactic_ids: list = None, pretty: bool = False, wait_for_complete: bool = False,
                      offset: int = None, limit: int = None, sort: str = None, search: str = None, select: list = None,
                      q: str = None, distinct: bool = False) -> ConnexionResponse:
    """Get information of specified MITRE's tactics.

    Parameters
    ----------
    tactic_ids : list
        List of tactic ids to be obtained.
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
    select : list
        Select which fields to return (separated by comma).
    sort : str
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    q : str
        Query to filter by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response with the MITRE's tactics information.
    """
    f_kwargs = {
        'filters': {
            'id': tactic_ids,
        },
        'offset': offset,
        'limit': limit,
        'sort_by': parse_api_param(sort, 'sort')['fields'] if sort else None,
        'sort_ascending': False if not sort or parse_api_param(sort, 'sort')['order'] == 'desc' else True,
        'search_text': parse_api_param(search, 'search')['value'] if search else None,
        'complementary_search': parse_api_param(search, 'search')['negation'] if search else None,
        'select': select,
        'q': q,
        'distinct': distinct
    }

    dapi = DistributedAPI(f=mitre.mitre_tactics,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_techniques(technique_ids: list = None, pretty: bool = False, wait_for_complete: bool = False,
                         offset: int = None, limit: int = None, sort: str = None, search: str = None,
                         select: list = None, q: str = None, distinct: bool = False) -> ConnexionResponse:
    """Get information of specified MITRE's techniques.

    Parameters
    ----------
    technique_ids : list, optional
        List of technique ids to be obtained.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.
    offset : int, optional
        First item to return.
    limit : int, optional
        Maximum number of items to return.
    search : str
        Looks for elements with the specified string.
    select : list[str]
        Select which fields to return (separated by comma).
    sort : str, optional
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    q : str
        Query to filter by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response with the MITRE's techniques information.
    """
    f_kwargs = {'filters': {
        'id': technique_ids,
    },
        'offset': offset,
        'limit': limit,
        'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else None,
        'sort_ascending': False if sort is None or parse_api_param(sort, 'sort')['order'] == 'desc' else True,
        'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
        'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
        'select': select, 
        'q': q,
        'distinct': distinct}

    dapi = DistributedAPI(f=mitre.mitre_techniques,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies'])

    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_mitigations(mitigation_ids: list = None, pretty: bool = False, wait_for_complete: bool = False,
                          offset: int = None, limit: int = None, sort: str = None, search: str = None,
                          select: list = None, q: str = None, distinct: bool = False) -> ConnexionResponse:
    """Get information of specified MITRE's mitigations.

    Parameters
    ----------
    mitigation_ids : list, optional
        List of mitigation ids to be obtained.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.
    offset : int, optional
        First item to return.
    limit : int, optional
        Maximum number of items to return.
    search : str
        Looks for elements with the specified string.
    select : list[str]
        Select which fields to return (separated by comma).
    sort : str, optional
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    q : str
        Query to filter by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response with the MITRE's mitigations information.
    """
    f_kwargs = {'filters': {
        'id': mitigation_ids,
    },
        'offset': offset,
        'limit': limit,
        'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else None,
        'sort_ascending': False if sort is None or parse_api_param(sort, 'sort')['order'] == 'desc' else True,
        'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
        'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
        'select': select,
        'q': q,
        'distinct': distinct}

    dapi = DistributedAPI(f=mitre.mitre_mitigations,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_groups(group_ids: list = None, pretty: bool = False, wait_for_complete: bool = False,
                     offset: int = None, limit: int = None, sort: str = None, search: str = None, select: list = None,
                     q: str = None, distinct: bool = False) -> ConnexionResponse:
    """Get information of specified MITRE's groups.

    Parameters
    ----------
    group_ids : list, optional
        List of group IDs to be obtained.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.
    offset : int, optional
        First item to return.
    limit : int, optional
        Maximum number of items to return.
    search : str
        Looks for elements with the specified string.
    select : list[str]
        Select which fields to return (separated by comma).
    sort : str, optional
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    q : str
        Query to filter by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response with the MITRE's groups information.
    """
    f_kwargs = {
        'filters': {
            'id': group_ids,
        },
        'offset': offset,
        'limit': limit,
        'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else None,
        'sort_ascending': False if sort is None or parse_api_param(sort, 'sort')['order'] == 'desc' else True,
        'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
        'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
        'select': select,
        'q': q,
        'distinct': distinct}

    dapi = DistributedAPI(f=mitre.mitre_groups,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies']
                          )
    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)


async def get_software(software_ids: list = None, pretty: bool = False, wait_for_complete: bool = False,
                       offset: int = None, limit: int = None, sort: str = None, search: str = None, select: list = None,
                       q: str = None, distinct: bool = False) -> ConnexionResponse:
    """Get information of specified MITRE's software.

    Parameters
    ----------
    software_ids : list, optional
        List of softwware IDs to be obtained.
    pretty : bool, optional
        Show results in human-readable format.
    wait_for_complete : bool, optional
        Disable timeout response.
    offset : int, optional
        First item to return.
    limit : int, optional
        Maximum number of items to return.
    search : str
        Looks for elements with the specified string.
    select : list[str]
        Select which fields to return (separated by comma).
    sort : str, optional
        Sorts the collection by a field or fields (separated by comma). Use +/- at the beginning to list in
        ascending or descending order.
    q : str
        Query to filter by.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    ConnexionResponse
        API response with the MITRE's software information.
    """
    f_kwargs = {
        'filters': {
            'id': software_ids,
        },
        'offset': offset,
        'limit': limit,
        'sort_by': parse_api_param(sort, 'sort')['fields'] if sort is not None else None,
        'sort_ascending': False if sort is None or parse_api_param(sort, 'sort')['order'] == 'desc' else True,
        'search_text': parse_api_param(search, 'search')['value'] if search is not None else None,
        'complementary_search': parse_api_param(search, 'search')['negation'] if search is not None else None,
        'select': select,
        'q': q,
        'distinct': distinct}

    dapi = DistributedAPI(f=mitre.mitre_software,
                          f_kwargs=remove_nones_to_dict(f_kwargs),
                          request_type='local_any',
                          is_async=False,
                          wait_for_complete=wait_for_complete,
                          logger=logger,
                          rbac_permissions=request.context['token_info']['rbac_policies'])

    data = raise_if_exc(await dapi.distribute_function())

    return json_response(data, pretty=pretty)
