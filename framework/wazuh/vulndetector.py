# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import typing
from wazuh import common
from wazuh.database import Connection
from wazuh.exception import WazuhException
from wazuh.utils import WazuhDBQuery, WazuhDBQueryGroupBy


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

#default_query_vulndetector = 'SELECT {0} FROM VULNERABILITIES_INFO'


class WazuhDBQueryVulnDetector(WazuhDBQuery):

    def __init__(self, offset=0, limit=common.database_limit, sort=None,
                 search=None, select=None, query='', count=True,
                 table='vulnerabilities_info', get_data=True, filters={},
                 default_sort_field='ID', fields=fields_vuln_info):

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table=table, sort=sort,
                              search=search, select=select, query=query, fields=fields,
                              default_sort_field=default_sort_field, db_path=common.vulndetector_db,
                              count=count, get_data=get_data, default_sort_order='ASC', filters=filters)


class WazuhDBQueryVulnDetectorGroupBy(WazuhDBQueryGroupBy):

    def __init__(self, filter_fields=None, offset=0, limit=common.database_limit, sort=None,
                 search=None, select=None, query='', count=True,
                 table='vulnerabilities_info', get_data=True, filters={},
                 default_sort_field='ID', fields=fields_vuln):

        WazuhDBQueryGroupBy.__init__(self, filter_fields=filter_fields, offset=offset, limit=limit, table=table, sort=sort,
                              search=search, select=select, query=query, fields=fields,
                              default_sort_field=default_sort_field, db_path=common.vulndetector_db,
                              count=count, get_data=get_data, default_sort_order='ASC', filters=filters)


def get_vulnerabilities_info(offset=0, limit=common.database_limit, sort=None,
                        search=None, select=None, filters={}, q='') -> typing.Dict:
    """
    Gets information about vulnerabilities.

    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    if select is None:
        select = {'fields': list(fields_vuln_info.keys())}

    db_query = WazuhDBQueryVulnDetector(offset=offset, limit=limit, sort=sort,
                                        search=search, select=select, filters=filters,
                                        query=q, table='vulnerabilities_info')

    return db_query.run()


def get_num_vulnerabilities(offset=0, limit=common.database_limit, sort=None,
                            search=None, select=None, filters={},
                            q='') -> typing.Dict:
    """
    Gets the number of vulnerabilities group by OS.

    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """

    if select is None:
        select = {'fields': list(fields_vuln.keys())}

    db_query = WazuhDBQueryVulnDetectorGroupBy(filter_fields={'fields': ['os']}, offset=offset, limit=limit, sort=sort,
                                               search=search, select=select, filters=filters,
                                               query=q, table='vulnerabilities',
                                               default_sort_field='cveid')

    return db_query.run()


severity = {'redhat': ('critical', 'important', 'low', 'moderate'),
            'ubuntu': ('High', 'Low', 'Medium', 'Negligible', 'Unknown', 'Untriaged'),
            'debian': ('Unknown')
            }