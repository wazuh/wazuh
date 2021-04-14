# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from functools import lru_cache
from typing import Dict

from wazuh.core import common, mitre
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.rbac.decorators import expose_resources
from wazuh.core.utils import process_array

logger = logging.getLogger('wazuh')


@lru_cache(maxsize=None)
def get_techniques():
    """TODO
    """
    db_query = mitre.WazuhDBQueryMitreTechniques(limit=None)
    data = db_query.run()

    return data


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


# def mitre_techniques(filters: dict = None, select: list = None, search: dict = None, offset: int = 0,
#                      limit: int = common.database_limit, sort: dict = None, q: str = None) -> Dict:
@expose_resources(actions=["mitre:read"], resources=["*:*:*"])
def mitre_techniques(filters: dict = None, offset=0, limit=common.database_limit, sort_by=None, sort_ascending=True,
                     search_text=None, complementary_search=False, search_in_fields=None, q='') -> Dict:
    """TODO
    """
    result = AffectedItemsWazuhResult(none_msg='No Techniques information was returned',
                                      all_msg='Techniques information was returned')
    data = get_techniques()
    data = process_array(data, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by,
                         sort_ascending=sort_ascending, offset=offset, limit=limit, q=q)

    result.affected_items.extend(data['items'])
    result.total_affected_items = data['totalItems']

    return result
