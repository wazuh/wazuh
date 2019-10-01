# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

from datetime import datetime, timezone, timedelta
from wazuh import common
from wazuh.utils import WazuhDBQueryDistinct, WazuhDBQuery, WazuhDBQueryGroupBy, SQLiteBackend, get_fields_to_nest, \
    plain_dict_to_nested_dict
from wazuh.exception import WazuhError
from wazuh.ossec_queue import OssecQueue
from glob import glob

fields = {'id': 'id', 'name': 'name', 'ip': 'coalesce(ip,register_ip)', 'status': 'status',
          'os.name': 'os_name', 'os.version': 'os_version', 'os.platform': 'os_platform',
          'version': 'version', 'manager': 'manager_host', 'dateAdd': 'date_add',
          'group': '`group`', 'mergedSum': 'merged_sum', 'configSum': 'config_sum',
          'os.codename': 'os_codename', 'os.major': 'os_major', 'os.minor': 'os_minor',
          'os.uname': 'os_uname', 'os.arch': 'os_arch', 'os.build': 'os_build',
          'node_name': 'node_name', 'lastKeepAlive': 'last_keepalive', 'internal_key': 'internal_key',
          'registerIP': 'register_ip'}


class WazuhDBQueryAgents(WazuhDBQuery):

    def __init__(self, offset=0, limit=common.database_limit, sort=None, search=None, select=None, count=True,
                 get_data=True, query='', filters=None, default_sort_field='id', min_select_fields=None,
                 remove_extra_fields=True):
        if filters is None:
            filters = {}
        if min_select_fields is None:
            min_select_fields = {'lastKeepAlive', 'version', 'id'}
        backend = SQLiteBackend(common.database_path_global)
        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table='agent', sort=sort, search=search, select=select,
                              filters=filters, fields=fields, default_sort_field=default_sort_field,
                              default_sort_order='ASC', query=query, backend=backend,
                              min_select_fields=min_select_fields, count=count, get_data=get_data,
                              date_fields={'lastKeepAlive', 'dateAdd'}, extra_fields={'internal_key'})
        self.remove_extra_fields = remove_extra_fields

    def _filter_status(self, status_filter):
        # set the status value to lowercase in case it's a string. If not, the value will be return unmodified.
        status_filter['value'] = getattr(status_filter['value'], 'lower', lambda: status_filter['value'])()
        result = datetime.utcnow() - timedelta(seconds=common.limit_seconds)
        self.request['time_active'] = result.replace(tzinfo=timezone.utc).timestamp()
        if status_filter['operator'] == '!=':
            self.query += 'NOT '

        if status_filter['value'] == 'active':
            self.query += '(last_keepalive >= :time_active AND version IS NOT NULL) or id = 0'
        elif status_filter['value'] == 'disconnected':
            self.query += 'last_keepalive < :time_active'
        elif status_filter['value'] == "never_connected":
            self.query += 'last_keepalive IS NULL AND id != 0'
        elif status_filter['value'] == 'pending':
            self.query += 'last_keepalive IS NOT NULL AND version IS NULL'
        else:
            raise WazuhError(1729, extra_message=status_filter['value'])

    def _filter_date(self, date_filter, filter_db_name):
        WazuhDBQuery._filter_date(self, date_filter, filter_db_name)
        self.query = self.query[:-1] + ' AND id != 0'

    def _sort_query(self, field):
        if field == 'status':
            # Order by status ASC is the same that order by last_keepalive DESC.
            return '{} {}'.format('last_keepAlive', self.sort['order'])
        elif field == 'os.version':
            return "CAST(os_major AS INTEGER) {0}, CAST(os_minor AS INTEGER) {0}".format(self.sort['order'])
        else:
            return WazuhDBQuery._sort_query(self, field)

    def _add_search_to_query(self):
        # since id are stored in database as integers, id searches must be turned into integers to work as expected.
        if self.search:
            del self.fields['id']
            WazuhDBQuery._add_search_to_query(self)
            self.fields['id'] = 'id'
            self.query = self.query[:-1] + ' OR id LIKE :search_id)'
            self.request['search_id'] = int(self.search['value']) if self.search['value'].isdigit() \
                else self.search['value']

    def _format_data_into_dictionary(self):
        def format_fields(field_name, value, today, lastKeepAlive=None, version=None):
            if field_name == 'id':
                return str(value).zfill(3)
            elif field_name == 'status':
                return calculate_status(lastKeepAlive, version is None, today)
            elif field_name == 'group':
                return value.split(',')
            elif field_name in ['dateAdd', 'lastKeepAlive']:
                return datetime.utcfromtimestamp(value)
            else:
                return value

        fields_to_nest, non_nested = get_fields_to_nest(self.fields.keys(), ['os'], '.')

        today = datetime.utcnow()

        # compute 'status' field, format id with zero padding and remove non-user-requested fields.
        # Also remove, extra fields (internal key and registration IP)
        selected_fields = self.select - self.extra_fields if self.remove_extra_fields else self.select
        selected_fields |= {'id'}
        self._data = [{key: format_fields(key, value, today, item.get('lastKeepAlive'), item.get('version'))
                      for key, value in item.items() if key in selected_fields} for item in self._data]

        self._data = [plain_dict_to_nested_dict(d, fields_to_nest, non_nested, ['os'], '.') for d in self._data]

        return super()._format_data_into_dictionary()

    def _parse_legacy_filters(self):
        if 'older_than' in self.legacy_filters:
            if self.legacy_filters['older_than'] is not None:
                self.q += (';' if self.q else '') + \
                          "(lastKeepAlive>{0};status!=never_connected,dateAdd>{0};status=never_connected)".format(
                              self.legacy_filters['older_than'])
            del self.legacy_filters['older_than']
        WazuhDBQuery._parse_legacy_filters(self)

    def _process_filter(self, field_name, field_filter, q_filter):
        if field_name == 'group' and q_filter['value'] is not None:
            field_filter_1, field_filter_2, field_filter_3 = \
                field_filter + '_1', field_filter + '_2', field_filter + '_3'
            self.query += '{0} LIKE :{1} OR {0} LIKE :{2} OR {0} LIKE :{3} OR {0} = :{4}'.format(
                self.fields[field_name], field_filter_1, field_filter_2, field_filter_3, field_filter)
            self.request[field_filter_1] = '%,' + q_filter['value']
            self.request[field_filter_2] = q_filter['value'] + ',%'
            self.request[field_filter_3] = '%,{},%'.format(q_filter['value'])
            self.request[field_filter] = q_filter['value']
        else:
            WazuhDBQuery._process_filter(self, field_name, field_filter, q_filter)


class WazuhDBQueryDistinctAgents(WazuhDBQueryDistinct, WazuhDBQueryAgents):
    pass


class WazuhDBQueryGroupByAgents(WazuhDBQueryGroupBy, WazuhDBQueryAgents):
    def __init__(self, filter_fields, *args, **kwargs):
        WazuhDBQueryAgents.__init__(self, *args, **kwargs)
        WazuhDBQueryGroupBy.__init__(self, *args, table=self.table, fields=self.fields, filter_fields=filter_fields,
                                     default_sort_field=self.default_sort_field, backend=self.backend, **kwargs)
        self.remove_extra_fields = True


class WazuhDBQueryMultigroups(WazuhDBQueryAgents):
    def __init__(self, group_id, query='', *args, **kwargs):
        self.group_id = group_id
        query = 'group={}'.format(group_id) + (';'+query if query else '')
        WazuhDBQueryAgents.__init__(self, query=query, *args, **kwargs)

    def _default_query(self):
        return "SELECT {0} FROM agent a LEFT JOIN belongs b ON a.id = b.id_agent" if self.group_id != "null" \
                                                                                  else "SELECT {0} FROM agent a"

    def _default_count_query(self):
        return 'COUNT(DISTINCT a.id)'

    def _get_total_items(self):
        WazuhDBQueryAgents._get_total_items(self)
        self.query += ' GROUP BY a.id '


def calculate_status(last_keep_alive, pending, today=datetime.utcnow()):
    """Calculates state based on last keep alive
    """
    if not last_keep_alive:
        return "never_connected"
    else:
        last_date = datetime.utcfromtimestamp(last_keep_alive)
        difference = (today - last_date).total_seconds()
        return "disconnected" if difference > common.limit_seconds else ("pending" if pending else "active")


def check_group_exists(group_id):
    """ Check if agent group exists

    :param group_id: Group ID.
    :return: Exception if group does not exist
    """
    if group_id != 'null' and not glob("{}/{}".format(common.shared_path, group_id)) and \
            not glob("{}/{}".format(common.multi_groups_path, group_id)):
        raise WazuhError(1710, extra_message=group_id)


def send_restart_command(agent_id):
    """ Send restart command to an agent

    :param agent_id: Agent ID
    :return OSSEC message
    """
    oq = OssecQueue(common.ARQUEUE)
    ret_msg = oq.send_msg_to_agent(OssecQueue.RESTART_AGENTS, agent_id)
    oq.close()

    return ret_msg


def send_restart_command_all():
    """Send restart command to all agents

    :return: OSSEC message
    """
    oq = OssecQueue(common.ARQUEUE)
    ret_msg = oq.send_msg_to_agent(OssecQueue.RESTART_AGENTS)
    oq.close()

    return ret_msg
