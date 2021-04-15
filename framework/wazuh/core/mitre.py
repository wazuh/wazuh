# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

from functools import lru_cache

from wazuh.core import common
from wazuh.core.utils import WazuhDBQuery, WazuhDBBackend
from wazuh.core.utils import process_array


class WazuhDBQueryMitre(WazuhDBQuery):

    def __init__(self, offset: int = 0, limit: int = common.database_limit, query: str = '', count: bool = True,
                 table: str = '', sort: dict = None, default_sort_field: str = 'id', default_sort_order='ASC',
                 fields=None, search: dict = None, select: list = None, min_select_fields=None, filters=None,
                 request_slice=500):
        """Create an instance of WazuhDBQueryMitre query."""

        if filters is None:
            filters = {}

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table=table, sort=sort, search=search, select=select,
                              fields=fields, default_sort_field=default_sort_field,
                              default_sort_order=default_sort_order, filters=filters, query=query, count=count,
                              get_data=True, min_select_fields=min_select_fields,
                              backend=WazuhDBBackend(query_format='mitre', request_slice=request_slice))

        self.relation_fields = set()  # This variable contains valid fields not included in the database (relations)

    def _filter_status(self, status_filter):
        pass


class WazuhDBQueryMitreMetadata(WazuhDBQueryMitre):

    def __init__(self):
        """Create an instance of WazuhDBQueryMitreMetadata query."""

        min_select_fields = {'key', 'value'}
        fields = {'key': 'key', 'value': 'value'}

        WazuhDBQueryMitre.__init__(self, table='metadata', min_select_fields=min_select_fields, fields=fields,
                                   default_sort_field='key')

    def _filter_status(self, status_filter):
        pass


class WazuhDBQueryMitreRelational(WazuhDBQueryMitre):

    def __init__(self, table: str = None, offset: int = 0, limit: int = common.database_limit, query: str = '',
                 count: bool = True, sort: dict = None, default_sort_order: str = 'ASC',
                 default_sort_field: str = None, fields=None, search: dict = None, select: list = None,
                 min_select_fields=None, filters=None, dict_key: str = None, request_slice=500):
        """WazuhDBQueryMitreRelational constructor
        This class will always generate dictionaries with two keys, this is because it handles relational tables,
        where the relationship of two objects is specified.

        Parameters
        ----------
        dict_key : str
            The value of this key will be the key of the output dictionary.
            The value of the output dictionary will be the value of the remaining key.
        """

        if filters is None:
            filters = {}
        if min_select_fields is None:
            if table == 'phase':
                self.min_select_fields = {'tactic_id', 'tech_id'}
                default_sort_field = 'tactic_id'
            elif table == 'mitigate' or table == 'use':
                # source_id = mitigation_id or group_id or software_id, target_id = technique_id
                self.min_select_fields = {'source_id', 'target_id'}
                default_sort_field = 'source_id'
        else:
            self.min_select_fields = min_select_fields
        if fields is None:
            if table == 'phase':
                fields = {'tactic_id': 'tactic_id', 'tech_id': 'tech_id'}
            elif table == 'mitigate':
                fields = {'source_id': 'source_id', 'target_id': 'target_id'}
            elif table == 'use':
                fields = {'source_id': 'source_id', 'source_type': 'source_type',
                          'target_id': 'target_id', 'target_type': 'target_type'}
        self.dict_key = dict_key if dict_key else next(iter(self.min_select_fields))

        WazuhDBQueryMitre.__init__(self, table=table, min_select_fields=self.min_select_fields, fields=fields,
                                   filters=filters, offset=offset, limit=limit, query=query, count=count,
                                   sort=sort, default_sort_field=default_sort_field,
                                   default_sort_order=default_sort_order, search=search, select=select,
                                   request_slice=request_slice)

    def _filter_status(self, status_filter):
        pass

    def _format_data_into_dictionary(self):
        """This function generates a dictionary where the key will be the value of the key that dict_key contains
         and the value will be the value of the remaining key.

        Returns
        -------
        Dictionary where the key will be the value of the key that dict_key contains and
        the value will be the value of the remaining key.
        """
        relational_dict = dict()
        for t in self._data:
            if t[self.dict_key] not in relational_dict:
                relational_dict[t[self.dict_key]] = list()
            second_key = list(self.min_select_fields)
            second_key.remove(self.dict_key)
            relational_dict[t[self.dict_key]].append(t[second_key[-1]])

        return relational_dict


class WazuhDBQueryMitreTechniques(WazuhDBQueryMitre):

    def __init__(self, offset: int = 0, limit: int = common.database_limit, query: str = '', count: bool = True,
                 sort: dict = None, default_sort_field: str = 'id', default_sort_order='ASC',
                 fields=None, search: dict = None, select: list = None, min_select_fields=None, filters=None):
        """Create an instance of WazuhDBQueryMitreTechniques query."""

        if select is None:
            select = set()
        if filters is None:
            filters = dict()
        self.min_select_fields = min_select_fields
        if min_select_fields is None:
            self.min_select_fields = {'id'}
        self.fields = fields
        if fields is None:
            self.fields = {'id': 'id', 'name': 'name', 'description': 'description', 'created_time': 'created_time',
                           'modified_time': 'modified_time', 'mitre_version': 'mitre_version',
                           'mitre_detection': 'mitre_detection', 'network_requirements': 'network_requirements',
                           'remote_support': 'remote_support', 'revoked_by': 'revoked_by', 'deprecated': 'deprecated',
                           'subtechnique_of': 'subtechnique_of'}

        WazuhDBQueryMitre.__init__(self, table='technique', min_select_fields=self.min_select_fields,
                                   fields=self.fields, filters=filters, offset=offset, limit=limit, query=query,
                                   count=count, sort=sort, default_sort_field=default_sort_field,
                                   default_sort_order=default_sort_order, search=search,
                                   select=list(set(self.fields.values()).intersection(set(select))),
                                   request_slice=32)

        self.relation_fields = {'related_tactics', 'related_mitigations', 'related_software', 'related_groups'}

    def _filter_status(self, status_filter):
        pass

    def _execute_data_query(self):
        """This function will add to the result the mitigations, groups, software and tactics
        related to each technique.
        """
        super()._execute_data_query()

        technique_ids = set()
        for technique in self._data:
            technique_ids.add(technique['id'])

        related_tactics = WazuhDBQueryMitreRelational(table='phase', filters={'tech_id': list(technique_ids)},
                                                      dict_key='tech_id', request_slice=250).run()
        related_mitigations = WazuhDBQueryMitreRelational(table='mitigate', filters={'target_id': list(technique_ids)},
                                                          dict_key='target_id', request_slice=250).run()
        related_software = WazuhDBQueryMitreRelational(table='use',
                                                       filters={'target_id': list(technique_ids),
                                                                'target_type': 'technique', 'source_type': 'software'},
                                                       dict_key='target_id', request_slice=250).run()
        related_groups = WazuhDBQueryMitreRelational(table='use',
                                                    filters={'target_id': list(technique_ids),
                                                             'target_type': 'technique', 'source_type': 'group'},
                                                    dict_key='target_id', request_slice=250).run()

        for technique in self._data:
            technique['related_tactics'] = related_tactics.get(technique['id'], list())
            technique['related_mitigations'] = related_mitigations.get(technique['id'], list())
            technique['related_software'] = related_software.get(technique['id'], list())
            technique['related_groups'] = related_groups.get(technique['id'], list())


@lru_cache(maxsize=None)
def get_techniques():
    """This function loads the technique data in order to speed up the use of the Framework function.
    It also provides information about the min_select_fields for the select parameter and the
    allowed_fields for the sort parameter.

    Returns
    -------
    dict
        Dictionary with information about the fields of the technique objects and the techniques obtained.
    """
    info = {'min_select_fields': None, 'allowed_fields': None}
    db_query = WazuhDBQueryMitreTechniques(limit=None)
    info['allowed_fields'] = set(db_query.fields.keys()).union(set(db_query.relation_fields))
    info['min_select_fields'] = set(db_query.min_select_fields)
    data = db_query.run()

    return info, data


def get_results_with_select(mitre_function, filters, select, offset, limit, sort_by, sort_ascending, search_text,
                            complementary_search, search_in_fields, q):
    """Sanitize the select parameter and processes the list of MITRE resources.

    Parameters
    ----------
    mitre_function : callable
        Cached function to obtain certain MITRE resources.
    filters : str
        Define field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}
    select : list
        Select which fields to return (separated by comma).
    offset : int
        First item to return
    limit : int
        Maximum number of items to return

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
    list
        Processed MITRE resources array.
    """
    fields_info, data = mitre_function()

    return process_array(data['items'], filters=filters, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, select=select,
                         sort_ascending=sort_ascending, offset=offset, limit=limit, q=q,
                         allowed_sort_fields=fields_info['allowed_fields'],
                         allowed_select_fields=fields_info['allowed_fields'],
                         required_fields=fields_info['min_select_fields'])
