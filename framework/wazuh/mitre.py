# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from typing import Dict

from wazuh.core import common, mitre
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.rbac.decorators import expose_resources

logger = logging.getLogger('wazuh')


@expose_resources(actions=["mitre:read"], resources=["*:*:*"])
def mitre_metadata() -> Dict:
    """Return the metadata of the MITRE's database

    Returns
    -------
    Metadata of MITRE's db
    """
    result = AffectedItemsWazuhResult(none_msg='No metadata information was returned',
                                      all_msg='Metadata information was returned')

    db_query = mitre.WazuhDBQueryMitreMetadata()
    data = db_query.run()

    result.affected_items.extend(data['items'])
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=["mitre:read"], resources=["*:*:*"])
def mitre_techniques(filters: dict = None, offset=0, limit=common.database_limit, select=None, sort_by=None,
                     sort_ascending=True, search_text=None, complementary_search=False,
                     search_in_fields=None, q='') -> Dict:
    """Get information of specified MITRE's techniques and its relations.

    Parameters
    ----------
    filters : str
        Define field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}
    offset : int
        First item to return
    limit : int
        Maximum number of items to return
    select : list
        Select which fields to return (separated by comma).
    sort_by : dict
        Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order
    search_text : str
        Text to search
    complementary_search : bool
        Find items without the text to search
    search_in_fields : list
        Fields to search in
    q : str
        Query for filtering a list of results.

    Returns
    -------
    dict
        Dictionary with the information of the specified techniques and their relationships
    """
    data = mitre.get_results_with_select(mitre.get_techniques, **locals())

    result = AffectedItemsWazuhResult(none_msg='No MITRE techniques information was returned',
                                      all_msg='MITRE techniques information was returned')
    result.affected_items.extend(data['items'])
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=["mitre:read"], resources=["*:*:*"])
def mitre_tactics(filters: dict = None, offset: int = 0, limit: int = common.database_limit, select: list = None,
                  sort_by: dict = None, sort_ascending: bool = True, search_text: str = None,
                  complementary_search: bool = False, search_in_fields: list = None, q: str = '') -> dict:
    """Get information of specified MITRE's tactics and its relations.

    Parameters
    ----------
    filters : dict
        Define field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
    select : list
        Select which fields to return (separated by comma).
    sort_by : dict
        Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order.
    search_text : str
        Text to search.
    complementary_search : bool
        Find items without the text to search.
    search_in_fields : list
        Fields to search in.
    q : str
        Query for filtering a list of results.

    Returns
    -------
    dict
        Dictionary with the information of the specified techniques and their relationships
    """
    data = mitre.get_results_with_select(mitre.get_tactics, **locals())

    result = AffectedItemsWazuhResult(none_msg='No tactics information was returned',
                                      all_msg='All tactics information was returned')
    result.affected_items.extend(data['items'])
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=["mitre:read"], resources=["*:*:*"])
def mitre_groups(filters: dict = None, offset: int = 0, limit: int = common.database_limit, select: list = None,
                 sort_by: dict = None, sort_ascending: bool = True, search_text: str = None,
                 complementary_search: bool = False, search_in_fields: list = None, q: str = '') -> Dict:
    """Get information of specified MITRE's groups and its relations.

    Parameters
    ----------
    filters : str
        Define field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}
    offset : int
        First item to return
    limit : int
        Maximum number of items to return
    select : list
        Select which fields to return (separated by comma).
    sort_by : dict
        Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order
    search_text : str
        Text to search
    complementary_search : bool
        Find items without the text to search
    search_in_fields : list
        Fields to search in
    q : str
        Query for filtering a list of results.

    Returns
    -------
    dict
        Dictionary with the information of the specified groups and their relationships.
    """
    data = mitre.get_results_with_select(mitre.get_groups, **locals())

    result = AffectedItemsWazuhResult(none_msg='No MITRE groups information was returned',
                                      all_msg='MITRE groups information was returned')
    result.affected_items.extend(data['items'])
    result.total_affected_items = data['totalItems']

    return result
