# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from typing import Dict

from wazuh import common
from wazuh.database import Connection
from wazuh.exception import WazuhException
from wazuh.utils import WazuhDBQuery, WazuhDBQueryGroupBy, SQLiteBackend


# API field -> DB field
fields_vuln_info = {'id': 'id',
                    'title': 'title',
                    'severity': 'severity',
                    'published': 'published',
                    'updated': 'updated',
                    'reference': 'reference',
                    'os': 'os',
                    'rationale': 'rationale',
                    'cvss': 'cvss',
                    'cvss_vector': 'cvss_vector',
                    'cvss3': 'cvss3',
                    'bugzilla_reference': 'bugzilla_reference',
                    'cwe': 'cwe',
                    'advisories': 'advisories'
                    }

fields_vuln = {'cveid': 'cveid',
               'os': 'os',
               'os_minor': 'os_minor',
               'package': 'package',
               'pending': 'pending',
               'operation': 'operation',
               'operation_value': 'operation_value',
               'check_vars': 'check_vars'
               }

# default_query_vulndetector = 'SELECT {0} FROM VULNERABILITIES_INFO'


class WazuhDBQueryVulnDetector(WazuhDBQuery):
    """Create a query against Vulnerability Detector database."""

    def __init__(self, offset: int=0, limit: int=common.database_limit,
                 sort: Dict={}, search: Dict={}, select: Dict={},
                 query: str='', count: bool=True, get_data: bool=True,
                 table: str='vulnerabilities_info', filters: Dict={},
                 default_sort_field: str='ID', fields: Dict=fields_vuln_info):
        """
        Constructor for WazuhDBQueryVulnDetector class.

        :param offset: First item to return
        :param limit: Maximum number of items to return
        :param sort: Sorts the items. Format: {"fields": ["field1", "field2"], "order": "asc|desc"}
        :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
        :param select: Select fields to return. Format: {"fields": ["field1", "field2"]}
        :param filters: Defines field filters required by the user. Format: {"field1": "value1", "field2": ["value2", "value3"]}
        :param query: Query to filter in database. Format: field operator value
        :param count: Whether to compute totalItems or not
        :param table: Table to do the query
        :param get_data: Whether to return data or not
        :param default_sort_order: By default, return elements sorted in this order
        :param fields: All available fields
        """

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table=table,
                              sort=sort, search=search, select=select,
                              query=query, fields=fields,
                              default_sort_field=default_sort_field,
                              count=count, get_data=get_data,
                              backend=SQLiteBackend(common.vulndetector_db),
                              default_sort_order='ASC', filters=filters)


class WazuhDBQueryVulnDetectorGroupBy(WazuhDBQueryGroupBy):
    """
    Create a query against Vulnerability Detector database.

    This class is used when a 'GROUP BY' clause is needed.
    """

    def __init__(self, filter_fields: Dict={}, offset: int=0,
                 limit: int=common.database_limit, sort: Dict={},
                 search: Dict={}, select: Dict={}, query: str='',
                 count: bool=True, table: str='vulnerabilities_info',
                 get_data: bool=True, filters: Dict={},
                 default_sort_field: str='ID', fields: Dict=fields_vuln_info):
        """
        Constructor for WazuhDBQueryVulnDetectorGroupBy class.

        :param filter_fields: Fields to group by. Format: {'fields': ['field1']}
        :param offset: First item to return
        :param limit: Maximum number of items to return
        :param sort: Sorts the items. Format: {"fields": ["field1", "field2"], "order": "asc|desc"}
        :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
        :param select: Select fields to return. Format: {"fields": ["field1", "field2"]}
        :param query: Query to filter in database. Format: field operator value
        :param count: Whether to compute totalItems or not
        :param table: Table to do the query
        :param get_data: Whether to return data or not
        :param filters: Defines field filters required by the user. Format: {"field1": "value1", "field2": ["value2", "value3"]}
        :param default_sort_order: By default, return elements sorted in this order
        :param fields: All available fields
        """

        WazuhDBQueryGroupBy.__init__(self, filter_fields=filter_fields,
                                     offset=offset, limit=limit, table=table,
                                     sort=sort, search=search, select=select,
                                     query=query, fields=fields,
                                     default_sort_field=default_sort_field,
                                     backend=SQLiteBackend(common.vulndetector_db),
                                     count=count, get_data=get_data,
                                     default_sort_order='ASC', filters=filters)


def get_vulnerabilities_info(offset: int=0, limit: int=common.database_limit,
                             sort: Dict={}, search: Dict={}, select: Dict={},
                             filters: Dict={}, q: str='') -> Dict:
    """
    Get information about vulnerabilities.

    :param offset: First item to return
    :param limit: Maximum number of items to return
    :param sort: Sorts the items. Format: {"fields": ["field1", "field2"], "order": "asc|desc"}
    :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
    :param select: Select fields to return. Format: {"fields": ["field1", "field2"]}
    :param filters: Defines field filters required by the user. Format: {"field1": "value1", "field2": ["value2", "value3"]}
    :param q: Query to filter in database. Format: field operator value

    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """

    if not select:
        select = {'fields': list(fields_vuln_info.keys())}

    db_query = WazuhDBQueryVulnDetector(offset=offset, limit=limit, sort=sort,
                                        search=search, select=select,
                                        filters=filters, query=q,
                                        table='vulnerabilities_info')

    return db_query.run()


def get_num_vulnerabilities(offset: int=0, limit: int=common.database_limit,
                            sort: Dict={}, search: Dict={}, select: Dict={},
                            filters: Dict={}, q: str='') -> Dict:
    """
    Get the number of vulnerabilities group by OS.

    :param offset: First item to return
    :param limit: Maximum number of items to return
    :param sort: Sorts the items. Format: {"fields": ["field1", "field2"], "order": "asc|desc"}
    :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
    :param select: Select fields to return. Format: {"fields": ["field1", "field2"]}
    :param filters: Defines field filters required by the user. Format: {"field1": "value1", "field2": ["value2", "value3"]}
    :param q: Query to filter in database. Format: field operator value

    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """

    if not select:
        select = {'fields': list(fields_vuln.keys())}

    db_query = WazuhDBQueryVulnDetectorGroupBy(filter_fields={'fields': ['os']},
                                               offset=offset, limit=limit,
                                               sort=sort, search=search,
                                               select=select, filters=filters,
                                               query=q, table='vulnerabilities',
                                               default_sort_field='cveid',
                                               fields=fields_vuln)

    return db_query.run()


severity = {'redhat': ('critical', 'important', 'low', 'moderate'),
            'ubuntu': ('High', 'Low', 'Medium', 'Negligible', 'Unknown', 'Untriaged'),
            'debian': ('Unknown')
            }
