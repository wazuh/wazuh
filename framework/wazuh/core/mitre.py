# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

from wazuh.core import common
from wazuh.core.utils import WazuhDBQuery, WazuhDBBackend


class WazuhDBQueryMitre(WazuhDBQuery):

    def __init__(self, offset: int = 0, limit: int = common.database_limit, query: str = '', count: bool = True,
                 table: str = 'technique', sort: dict = None, default_sort_field: str = 'id', default_sort_order='ASC',
                 fields=None, search: dict = None, select: list = None, min_select_fields=None, filters=None):
        """Create an instance of WazuhDBQueryMitre query."""

        if filters is None:
            filters = {}

        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table=table, sort=sort, search=search, select=select,
                              fields=fields, default_sort_field=default_sort_field,
                              default_sort_order=default_sort_order, filters=filters, query=query, count=count,
                              get_data=True, min_select_fields=min_select_fields,
                              backend=WazuhDBBackend(query_format='mitre'))

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
                 min_select_fields=None, filters=None, dict_key: str = None):
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
                                   default_sort_order=default_sort_order, search=search, select=select)

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
        if min_select_fields is None:
            min_select_fields = {'id', 'name'}
        if fields is None:
            fields = {'id': 'id', 'name': 'name', 'description': 'description', 'created_time': 'created_time',
                      'modified_time': 'modified_time', 'mitre_version': 'mitre_version',
                      'mitre_detection': 'mitre_detection', 'network_requirements': 'network_requirements',
                      'remote_support': 'remote_support', 'revoked_by': 'revoked_by', 'deprecated': 'deprecated',
                      'subtechnique_of': 'subtechnique_of'}

        self.extra_valid_select = {'related_tactics', 'related_mitigations', 'related_software', 'related_group'}
        self.user_select = min_select_fields.union(set(select))

        WazuhDBQueryMitre.__init__(self, table='technique', min_select_fields=min_select_fields, fields=fields,
                                   filters=filters, offset=offset, limit=limit, query=query, count=count,
                                   sort=sort, default_sort_field=default_sort_field,
                                   default_sort_order=default_sort_order, search=search,
                                   select=list(set(fields.values()).intersection(set(select))))

    def _filter_status(self, status_filter):
        pass

    def _process_filter(self, field_name, field_filter, q_filter):
        if 'technique_ids' in field_name:
            self.query += f"id {q_filter['operator']} (:{field_filter})"
            self.request[field_filter] = q_filter['value']
        else:
            super()._process_filter(field_name, field_filter, q_filter)

    def _delete_extra_fields(self):
        new_data = list()
        for technique in self._data:
            try:
                new_data.append({k: technique[k] for k in self.user_select})
            except KeyError:
                pass

        self._data = new_data

    def _format_data_into_dictionary(self):
        """This function will add to the final result the mitigations, groups, software and tactics
        related to each of the techniques.

        Returns
        -------
        Dictionary with all the requested techniques and their relationships.
        """
        technique_ids = set()
        for technique in self._data:
            technique_ids.add(technique['id'])

        related_tactics = WazuhDBQueryMitreRelational(table='phase', filters={'tech_id': list(technique_ids)},
                                                      dict_key='tech_id').run()
        related_mitigations = WazuhDBQueryMitreRelational(table='mitigate', filters={'target_id': list(technique_ids)},
                                                          dict_key='target_id').run()
        related_software = WazuhDBQueryMitreRelational(table='use',
                                                       filters={'target_id': list(technique_ids),
                                                                'target_type': 'technique', 'source_type': 'software'},
                                                       dict_key='target_id').run()
        related_group = WazuhDBQueryMitreRelational(table='use',
                                                    filters={'target_id': list(technique_ids),
                                                             'target_type': 'technique', 'source_type': 'group'},
                                                    dict_key='target_id').run()

        for technique in self._data:
            technique['related_tactics'] = related_tactics.get(technique['id'], list())
            technique['related_mitigations'] = related_mitigations.get(technique['id'], list())
            technique['related_software'] = related_software.get(technique['id'], list())
            technique['related_group'] = related_group.get(technique['id'], list())

        self._delete_extra_fields()

        return {'items': self._data, 'totalItems': self.total_items}
