# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core.agent import Agent
from wazuh.core.common import DATE_FORMAT
from wazuh.core.exception import WazuhException
from wazuh.core.utils import WazuhDBQuery, WazuhDBBackend, get_date_from_timestamp
from wazuh.core.wdb import WazuhDBConnection


class WazuhDBQueryRootcheck(WazuhDBQuery):
    """Rootcheck WazuhDBQuery object."""
    fields = {
        'status': 'status', 'log': 'log', 'date_first': 'date_first', 'date_last': 'date_last', 'pci_dss': 'pci_dss',
        'cis': 'cis'
    }

    def __init__(self, agent_id: str, offset: int, limit: int, sort: dict, search: dict, select: list, query: str,
                 count: bool, get_data: bool, distinct: bool, default_sort_field: str = 'date_last',
                 filters: dict = None, fields: dict = fields):
        """Class constructor.

        Parameters
        ----------
        agent_id : str
            Agent ID.
        offset : int
            First item to return.
        limit : int
            Maximum number of items to return.
        sort : dict
            Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        select : list
            Select fields to return. Format: ["field1","field2"].
        search : dict
            Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
        filters : dict
            Defines field filters required by the user. Format: {"field1":"value1", "field2":["value2","value3"]}
        query : str
            Query to filter in database. Format: field operator value.
        default_sort_field : str
            By default, return elements sorted by this field. Default: 'date_last'
        count : bool
            Whether to compute totalItems or not.
        get_data : bool
            Whether to return data or not.
        fields : dict
            Rootcheck fields.
        distinct : bool
            Look for distinct values.
        """

        if filters is None:
            filters = {}
        # Check if the agent exists
        Agent(agent_id).get_basic_information()
        backend = WazuhDBBackend(agent_id)
        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table='pm_event', sort=sort, search=search,
                              select=select, fields=fields, default_sort_field=default_sort_field,
                              default_sort_order='DESC', filters=filters, query=query, backend=backend,
                              min_select_fields=set(), count=count, get_data=get_data, distinct=distinct,
                              date_fields={'date_first', 'date_last'})

    def _default_query(self) -> str:
        """Get default query.

        Returns
        -------
        str
            Default query.
        """
        return "SELECT {0} FROM " if not self.distinct else "SELECT DISTINCT {0} FROM "

    def _parse_filters(self):
        """Parse query filters."""
        if self.legacy_filters:
            self._parse_legacy_filters()
        if self.q:
            self._parse_query()
        # Status filter can only appear once in the filter list
        statuses = list(filter(lambda x: x['field'].startswith('status'), self.query_filters))
        if statuses:
            for status in statuses:
                self.query_filters.remove(status)
            first_status = statuses[0]
            first_status['separator'] = 'AND' if first_status['separator'] == '' else first_status['separator']
            self.query_filters.insert(0, statuses[0])
            self.query_filters[-1]['separator'] = ''

    def _filter_status(self, filter_status: dict):
        """Add status filter to query.

        Parameters
        ----------
        filter_status : dict
            Dictionary containing the filters to add.

        Raises
        ------
        WazuhException(1603)
            Invalid status. Valid statuses are: all, solved and outstanding.
        """
        partial = "SELECT {0} AS status, date_first, date_last, log, pci_dss, cis FROM pm_event AS t WHERE " \
                  "date_last {1} (SELECT date_last-86400 FROM pm_event WHERE log = 'Ending rootcheck scan.')"
        log_not_in = ") WHERE log NOT IN ('Starting rootcheck scan.', 'Ending rootcheck scan.', " \
                     "'Starting syscheck scan.', 'Ending syscheck scan.'"

        if filter_status['value'] == 'all':
            self.query += partial.format("'outstanding'", '>') + " UNION " + partial.format("'solved'",
                                                                                            '<=') + log_not_in
        elif filter_status['value'] == 'outstanding':
            self.query += partial.format("'outstanding'", '>') + log_not_in
        elif filter_status['value'] == 'solved':
            self.query += partial.format("'solved'", '<=') + log_not_in
        else:
            raise WazuhException(1603, filter_status['value'])

    def _format_data_into_dictionary(self):
        def format_fields(field_name, value):
            return get_date_from_timestamp(value).strftime(DATE_FORMAT) \
                if field_name in ['date_first', 'date_last'] else value

        return {'items': [{field: format_fields(field, db_tuple[field]) for field in self.select |
                           self.min_select_fields if field in db_tuple and db_tuple[field] is not None}
                          for db_tuple in self._data], 'totalItems': self.total_items}

    def _process_filter(self, field_name, field_filter, q_filter):
        if field_name == "status":
            self._filter_status(q_filter)
        else:
            super()._process_filter(field_name, field_filter, q_filter)

    @staticmethod
    def _pass_filter(field, value):
        return False


def last_scan(agent_id: str) -> dict:
    """Get the last rootcheck scan of an agent.

    Parameters
    ----------
    agent_id : str
        Agent ID.

    Returns
    -------
    dict
        Dictionary: end, start.
    """
    Agent(agent_id).get_basic_information()
    wdb_conn = WazuhDBConnection()

    # end time
    result = wdb_conn.execute(f"agent {agent_id} sql SELECT max(date_last) FROM pm_event WHERE "
                              "log = 'Ending rootcheck scan.'")
    time = list(result[0].values())[0] if result else None
    end = get_date_from_timestamp(time).strftime(DATE_FORMAT) if time is not None else None

    # start time
    result = wdb_conn.execute(f"agent {agent_id} sql SELECT max(date_last) FROM pm_event "
                              "WHERE log = 'Starting rootcheck scan.'")
    time = list(result[0].values())[0] if result else None

    start = get_date_from_timestamp(time).strftime(DATE_FORMAT) if time is not None else None

    return {'start': start, 'end': None if start is None else None if end is None or end < start else end}


def rootcheck_delete_agent(agent: str, wdb_conn: WazuhDBConnection) -> None:
    """Send message to wdb to delete the rootcheck DB of an agent.

    Parameters
    ----------
    agent : str
        Agent ID.
    wdb_conn : WazuhDBConnection
        Object representing the connection to the wdb socket.
    """
    wdb_conn.execute(f"agent {agent} rootcheck delete", delete=True)
