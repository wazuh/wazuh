# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

import copy
from functools import lru_cache
from typing import Union

from wazuh.core import common
from wazuh.core.utils import WazuhDBQuery, WazuhDBBackend, get_utc_strptime
from wazuh.core.utils import process_array

# Optimal request_slice values for each WazuhDBQuery
# TACTICS_REQUEST_SLICE = 500  # Default WazuhDBQueryMitre request_slice value
MITIGATIONS_REQUEST_SLICE = 64
REFERENCES_REQUEST_SLICE = 128
GROUPS_REQUEST_SLICE = 64
SOFTWARE_REQUEST_SLICE = 64
TECHNIQUES_REQUEST_SLICE = 32
RELATIONAL_REQUEST_SLICE = 256

# Select used for each item's references
SELECT_FIELDS_REFERENCES = ['url', 'description', 'source', 'external_id']

# Extra fields from references
EXTRA_FIELDS = {'url', 'source', 'external_id'}


class WazuhDBQueryMitre(WazuhDBQuery):

    def __init__(self, offset: int = 0, limit: Union[int, None] = common.DATABASE_LIMIT, query: str = '',
                 count: bool = True, table: str = '', sort: dict = None, default_sort_field: str = 'id',
                 default_sort_order='ASC', fields=None, search: dict = None, select: list = None,
                 min_select_fields=None, filters=None, request_slice=500):
        """Create an instance of WazuhDBQueryMitre query."""

        if filters is None:
            filters = {}

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table=table, sort=sort, search=search, select=select,
                              fields=fields, default_sort_field=default_sort_field,
                              default_sort_order=default_sort_order, filters=filters, query=query, count=count,
                              get_data=True, min_select_fields=min_select_fields,
                              date_fields={'created_time', 'modified_time'},
                              backend=WazuhDBBackend(query_format='mitre', request_slice=request_slice))

        self.relation_fields = set()  # This variable contains valid fields not included in the database (relations)

    def _filter_status(self, status_filter):
        pass

    def _move_external_id_mitre_resource(self, mitre_resource: dict):
        """Extract the dictionary with external id, source and url from references and move it to the external level of
        the MITRE resource.

        Parameters
        ----------
        mitre_resource : dict
            MITRE resource we want to update the reference from.
        """
        # Take the reference with external_id checking it is not None and the source is mitre-attack
        reference_external_id = next((row_no_id for row_no_id in mitre_resource['references'] if
                                      row_no_id.get('external_id') and row_no_id.get('source') == 'mitre-attack'), {})
        if 'description' in reference_external_id:
            reference_external_id.pop('description')

        # Delete the reference from references and update the MITRE object
        if reference_external_id:
            mitre_resource['references'].remove(reference_external_id)
        mitre_resource.update(reference_external_id)

    def _format_data_into_dictionary(self):
        """Standardization of dates to the ISO 8601 format."""
        [t.update((k, get_utc_strptime(v, '%Y-%m-%d %H:%M:%S.%f').strftime(common.DECIMALS_DATE_FORMAT))
                  for k, v in t.items() if k in self.date_fields) for t in self._data]

        return {'items': self._data, 'totalItems': self.total_items}


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

    def __init__(self, table: str = None, offset: int = 0, limit: Union[int, None] = common.DATABASE_LIMIT,
                 query: str = '', count: bool = True, sort: dict = None, default_sort_order: str = 'ASC',
                 default_sort_field: str = None, fields=None, search: dict = None, select: list = None,
                 min_select_fields=None, filters=None, dict_key: str = None, request_slice=RELATIONAL_REQUEST_SLICE):
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
                # source_id refers to mitigation_id, group_id or software_id
                # target_id always refers to technique_id
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


class WazuhDBQueryMitreMitigations(WazuhDBQueryMitre):

    def __init__(self, offset: int = 0, limit: Union[int, None] = common.DATABASE_LIMIT, query: str = '',
                 count: bool = True, sort: dict = None, default_sort_field: str = 'id', default_sort_order='ASC',
                 fields=None, search: dict = None, select: list = None, min_select_fields=None, filters=None):
        """Create an instance of WazuhDBQueryMitreMitigations query."""

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
                           'revoked_by': 'revoked_by', 'deprecated': 'deprecated'}

        WazuhDBQueryMitre.__init__(self, table='mitigation', min_select_fields=self.min_select_fields,
                                   fields=self.fields, filters=filters, offset=offset, limit=limit, query=query,
                                   count=count, sort=sort, default_sort_field=default_sort_field,
                                   default_sort_order=default_sort_order, search=search,
                                   select=list(set(self.fields.values()).intersection(set(select))),
                                   request_slice=MITIGATIONS_REQUEST_SLICE)

        self.relation_fields = {'techniques', 'references'}
        self.extra_fields = EXTRA_FIELDS

    def _filter_status(self, status_filter):
        pass

    def _execute_data_query(self):
        """This function will add to the result the techniques related to each mitigation.
        """
        super()._execute_data_query()

        mitigation_ids = set()
        for mitigation in self._data:
            mitigation_ids.add(mitigation['id'])

        with WazuhDBQueryMitreRelational(table='mitigate', filters={'source_id': list(mitigation_ids)},
                                         dict_key='source_id', limit=None) as mitre_relational_query:
            techniques = mitre_relational_query.run()

        with WazuhDBQueryMitreReferences(limit=None, filters={'type': 'mitigation'},
                                         select=SELECT_FIELDS_REFERENCES) as mitre_references_query:
            references = mitre_references_query.run()

        references_no_id = copy.deepcopy(references)
        for row in references_no_id['items']:
            row.pop('id')

        for mitigation in self._data:
            mitigation['techniques'] = techniques.get(mitigation['id'], list())
            mitigation['references'] = [row_no_id for row, row_no_id in
                                        zip(references['items'], references_no_id['items']) if
                                        row['id'] == mitigation['id']]
            self._move_external_id_mitre_resource(mitigation)


class WazuhDBQueryMitreReferences(WazuhDBQueryMitre):

    def __init__(self, offset: int = 0, limit: Union[int, None] = common.DATABASE_LIMIT, query: str = '',
                 count: bool = True, sort: dict = None, default_sort_field: str = 'id', default_sort_order='ASC',
                 fields=None, search: dict = None, select: list = None, min_select_fields=None, filters=None):
        """Create an instance of WazuhDBQueryMitreReferences query."""

        if select is None:
            select = set()
        if filters is None:
            filters = dict()
        self.min_select_fields = min_select_fields
        if min_select_fields is None:
            self.min_select_fields = {'id'}
        self.fields = fields
        if fields is None:
            self.fields = {'id': 'id', 'source': 'source', 'external_id': 'external_id', 'url': 'url',
                           'description': 'description', 'type': 'type'}

        WazuhDBQueryMitre.__init__(self, table='reference', min_select_fields=self.min_select_fields,
                                   fields=self.fields, filters=filters, offset=offset, limit=limit, query=query,
                                   count=count, sort=sort, default_sort_field=default_sort_field,
                                   default_sort_order=default_sort_order, search=search,
                                   select=list(set(self.fields.values()).intersection(set(select))),
                                   request_slice=REFERENCES_REQUEST_SLICE)

    def _filter_status(self, status_filter):
        pass


class WazuhDBQueryMitreTactics(WazuhDBQueryMitre):

    def __init__(self, offset: int = 0, limit: Union[int, None] = common.DATABASE_LIMIT, query: str = '',
                 count: bool = True, sort: dict = None, default_sort_field: str = 'id', default_sort_order='ASC',
                 fields=None, search: dict = None, select: list = None, min_select_fields=None, filters=None):
        """Create an instance of WazuhDBQueryMitreTactics query."""

        if select is None:
            select = set()
        if filters is None:
            filters = dict()
        self.min_select_fields = min_select_fields
        if min_select_fields is None:
            self.min_select_fields = {'id'}
        self.fields = fields
        if fields is None:
            self.fields = {'id': 'id', 'name': 'name', 'description': 'description', 'short_name': 'short_name',
                           'created_time': 'created_time', 'modified_time': 'modified_time'}

        WazuhDBQueryMitre.__init__(self, table='tactic', min_select_fields=self.min_select_fields,
                                   fields=self.fields, filters=filters, offset=offset, limit=limit, query=query,
                                   count=count, sort=sort, default_sort_field=default_sort_field,
                                   default_sort_order=default_sort_order, search=search,
                                   select=list(set(self.fields.values()).intersection(set(select))))

        self.relation_fields = {'techniques', 'references'}
        self.extra_fields = EXTRA_FIELDS

    def _filter_status(self, status_filter):
        pass

    def _execute_data_query(self):
        """This function will add to the result the techniques related to each tactic."""
        super()._execute_data_query()

        tactic_ids = set()
        for tactic in self._data:
            tactic_ids.add(tactic['id'])

        with WazuhDBQueryMitreRelational(table='phase', filters={'tactic_id': list(tactic_ids)},
                                         dict_key='tactic_id', limit=None) as mitre_relational_query:
            techniques = mitre_relational_query.run()

        with WazuhDBQueryMitreReferences(limit=None, filters={'type': 'tactic'},
                                         select=SELECT_FIELDS_REFERENCES) as mitre_references_query:
            references = mitre_references_query.run()

        references_no_id = copy.deepcopy(references)
        for row in references_no_id['items']:
            row.pop('id')

        for tactic in self._data:
            tactic['techniques'] = techniques.get(tactic['id'], list())
            tactic['references'] = [row_no_id for row, row_no_id in
                                    zip(references['items'], references_no_id['items']) if
                                    row['id'] == tactic['id']]
            self._move_external_id_mitre_resource(tactic)


class WazuhDBQueryMitreTechniques(WazuhDBQueryMitre):

    def __init__(self, offset: int = 0, limit: Union[int, None] = common.DATABASE_LIMIT, query: str = '',
                 count: bool = True, sort: dict = None, default_sort_field: str = 'id', default_sort_order='ASC',
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
                                   request_slice=TECHNIQUES_REQUEST_SLICE)

        self.relation_fields = {'tactics', 'mitigations', 'software', 'groups', 'references'}
        self.extra_fields = EXTRA_FIELDS

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

        with WazuhDBQueryMitreRelational(table='phase', filters={'tech_id': list(technique_ids)},
                                         dict_key='tech_id', limit=None) as mitre_relational_query:
            tactics = mitre_relational_query.run()

        with WazuhDBQueryMitreRelational(table='mitigate', filters={'target_id': list(technique_ids)},
                                         dict_key='target_id', limit=None) as mitre_relational_query:
            mitigations = mitre_relational_query.run()

        with WazuhDBQueryMitreRelational(table='use',
                                         filters={'target_id': list(technique_ids),
                                                  'target_type': 'technique', 'source_type': 'software'},
                                         dict_key='target_id',
                                         limit=None) as mitre_relational_query:
            software = mitre_relational_query.run()

        with WazuhDBQueryMitreRelational(table='use',
                                         filters={'target_id': list(technique_ids),
                                                  'target_type': 'technique', 'source_type': 'group'},
                                         dict_key='target_id',
                                         limit=None) as mitre_relational_query:
            groups = mitre_relational_query.run()

        with WazuhDBQueryMitreReferences(limit=None, filters={'type': 'technique'},
                                         select=SELECT_FIELDS_REFERENCES) as mitre_references_query:
            references = mitre_references_query.run()

        references_no_id = copy.deepcopy(references)
        for row in references_no_id['items']:
            row.pop('id')

        for technique in self._data:
            technique['tactics'] = tactics.get(technique['id'], list())
            technique['mitigations'] = mitigations.get(technique['id'], list())
            technique['software'] = software.get(technique['id'], list())
            technique['groups'] = groups.get(technique['id'], list())
            technique['references'] = [row_no_id for row, row_no_id in
                                       zip(references['items'], references_no_id['items']) if
                                       row['id'] == technique['id']]
            self._move_external_id_mitre_resource(technique)


class WazuhDBQueryMitreGroups(WazuhDBQueryMitre):

    def __init__(self, offset: int = 0, limit: Union[int, None] = common.DATABASE_LIMIT, query: str = '',
                 count: bool = True, sort: dict = None, default_sort_field: str = 'id', default_sort_order='ASC',
                 fields=None, search: dict = None, select: list = None, min_select_fields=None, filters=None):
        """Create an instance of WazuhDBQueryMitreGroups query."""

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
                           'revoked_by': 'revoked_by', 'deprecated': 'deprecated'}

        WazuhDBQueryMitre.__init__(self, table='`group`', min_select_fields=self.min_select_fields,
                                   fields=self.fields, filters=filters, offset=offset, limit=limit, query=query,
                                   count=count, sort=sort, default_sort_field=default_sort_field,
                                   default_sort_order=default_sort_order, search=search,
                                   select=list(set(self.fields.values()).intersection(set(select))),
                                   request_slice=GROUPS_REQUEST_SLICE)

        self.relation_fields = {'software', 'techniques', 'references'}
        self.extra_fields = EXTRA_FIELDS

    def _filter_status(self, status_filter):
        pass

    def _execute_data_query(self):
        """This function will add to the result the software and tactics related to each group."""
        super()._execute_data_query()

        group_ids = set()
        for group in self._data:
            group_ids.add(group['id'])

        with WazuhDBQueryMitreRelational(table='use',
                                         filters={'source_id': list(group_ids),
                                                  'target_type': 'software', 'source_type': 'group'},
                                         dict_key='source_id',
                                         limit=None) as mitre_relational_query:
            software = mitre_relational_query.run()

        with WazuhDBQueryMitreRelational(table='use',
                                         filters={'source_id': list(group_ids),
                                                  'target_type': 'technique', 'source_type': 'group'},
                                         dict_key='source_id',
                                         limit=None) as mitre_relational_query:
            techniques = mitre_relational_query.run()

        with WazuhDBQueryMitreReferences(limit=None, filters={'type': 'group'},
                                         select=SELECT_FIELDS_REFERENCES) as mitre_references_query:
            references = mitre_references_query.run()

        references_no_id = copy.deepcopy(references)
        for row in references_no_id['items']:
            row.pop('id')

        for group in self._data:
            group['software'] = software.get(group['id'], list())
            group['techniques'] = techniques.get(group['id'], list())
            group['references'] = [row_no_id for row, row_no_id in
                                   zip(references['items'], references_no_id['items']) if
                                   row['id'] == group['id']]
            self._move_external_id_mitre_resource(group)


class WazuhDBQueryMitreSoftware(WazuhDBQueryMitre):

    def __init__(self, offset: int = 0, limit: Union[int, None] = common.DATABASE_LIMIT, query: str = '',
                 count: bool = True, sort: dict = None, default_sort_field: str = 'id', default_sort_order='ASC',
                 fields=None, search: dict = None, select: list = None, min_select_fields=None, filters=None):
        """Create an instance of WazuhDBQueryMitreSoftware query."""

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
                           'revoked_by': 'revoked_by', 'deprecated': 'deprecated'}

        WazuhDBQueryMitre.__init__(self, table='software', min_select_fields=self.min_select_fields,
                                   fields=self.fields, filters=filters, offset=offset, limit=limit, query=query,
                                   count=count, sort=sort, default_sort_field=default_sort_field,
                                   default_sort_order=default_sort_order, search=search,
                                   select=list(set(self.fields.values()).intersection(set(select))),
                                   request_slice=SOFTWARE_REQUEST_SLICE)

        self.relation_fields = {'groups', 'techniques', 'references'}
        self.extra_fields = EXTRA_FIELDS

    def _filter_status(self, status_filter):
        pass

    def _execute_data_query(self):
        """This function will add to the result the groups and techniques related to each software."""
        super()._execute_data_query()

        software_ids = set()
        for group in self._data:
            software_ids.add(group['id'])

        with WazuhDBQueryMitreRelational(table='use',
                                         filters={'target_id': list(software_ids),
                                                  'target_type': 'software',
                                                  'source_type': 'group'},
                                         dict_key='target_id',
                                         limit=None) as mitre_relational_query:
            groups = mitre_relational_query.run()

        with WazuhDBQueryMitreRelational(table='use',
                                         filters={'source_id': list(software_ids),
                                                  'target_type': 'technique',
                                                  'source_type': 'software'},
                                         dict_key='source_id',
                                         limit=None) as mitre_relational_query:
            techniques = mitre_relational_query.run()

        with WazuhDBQueryMitreReferences(limit=None, filters={'type': 'software'},
                                         select=SELECT_FIELDS_REFERENCES) as mitre_references_query:
            references = mitre_references_query.run()

        references_no_id = copy.deepcopy(references)
        for row in references_no_id['items']:
            row.pop('id')

        for software in self._data:
            software['groups'] = groups.get(software['id'], list())
            software['techniques'] = techniques.get(software['id'], list())
            software['references'] = [row_no_id for row, row_no_id in
                                      zip(references['items'], references_no_id['items']) if
                                      row['id'] == software['id']]
            self._move_external_id_mitre_resource(software)


@lru_cache(maxsize=None)
def get_mitre_items(mitre_class: callable):
    """This function loads the MITRE data in order to speed up the use of the Framework function.
    It also provides information about the min_select_fields for the select parameter and the
    allowed_fields for the sort parameter.

    Parameters
    ----------
    mitre_class : callable
        WazuhDBQueryMitre class used to obtain certain MITRE resources.

    Returns
    -------
    dict
        Dictionary with information about the fields of the MITRE objects and the items obtained.
    """
    info = {'min_select_fields': None, 'allowed_fields': None}
    db_query = mitre_class(limit=None)
    info['allowed_fields'] = \
        set(db_query.fields.keys()).union(set(db_query.relation_fields)).union(db_query.extra_fields)
    info['min_select_fields'] = set(db_query.min_select_fields)
    data = db_query.run()

    return info, data


def get_results_with_select(mitre_class: callable, filters: str, select: list, offset: int, limit: int, sort_by: dict,
                            sort_ascending: bool, search_text: str, complementary_search: bool, search_in_fields: list,
                            q: str) -> list:
    """Sanitize the select parameter and processes the list of MITRE resources.

    Parameters
    ----------
    mitre_class : callable
        WazuhDBQueryMitre class used to obtain certain MITRE resources.
    filters : str
        Define field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}
    select : list
        Select which fields to return (separated by comma).
    offset : int
        First item to return.
    limit : int
        Maximum number of items to return.
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
    list
        Processed MITRE resources array.
    """
    fields_info, data = get_mitre_items(mitre_class)

    return process_array(data['items'], filters=filters, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, select=select,
                         sort_ascending=sort_ascending, offset=offset, limit=limit, q=q,
                         allowed_sort_fields=fields_info['allowed_fields'],
                         allowed_select_fields=fields_info['allowed_fields'],
                         required_fields=fields_info['min_select_fields'])
