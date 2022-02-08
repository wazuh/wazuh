# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

import ipaddress
import json
import re
import threading
from base64 import b64encode
from datetime import datetime
from functools import lru_cache
from json import dumps, loads
from os import listdir, path
from shutil import rmtree

from wazuh.core import common, configuration, stats
from wazuh.core.InputValidator import InputValidator
from wazuh.core.cluster.utils import get_manager_status
from wazuh.core.common import AGENT_COMPONENT_STATS_REQUIRED_VERSION, date_format
from wazuh.core.exception import WazuhException, WazuhError, WazuhInternalError, WazuhResourceNotFound
from wazuh.core.utils import WazuhVersion, plain_dict_to_nested_dict, get_fields_to_nest, WazuhDBQuery, \
    WazuhDBQueryDistinct, WazuhDBQueryGroupBy, WazuhDBBackend
from wazuh.core.wazuh_queue import WazuhQueue
from wazuh.core.wazuh_socket import WazuhSocket, WazuhSocketJSON, create_wazuh_socket_message
from wazuh.core.wdb import WazuhDBConnection

detect_wrong_lines = re.compile(r'(.+ .+ (?:any|\d+\.\d+\.\d+\.\d+) \w+)')
detect_valid_lines = re.compile(r'^(\d{3,}) (.+) (any|\d+\.\d+\.\d+\.\d+) (\w+)', re.MULTILINE)

mutex = threading.Lock()
lock_file = None
lock_acquired = False

agent_regex = re.compile(r"^(\d{3,}) [^!].* .* .*$", re.MULTILINE)


class WazuhDBQueryAgents(WazuhDBQuery):

    def __init__(self, offset=0, limit=common.database_limit, sort=None, search=None, select=None, count=True,
                 get_data=True, query='', filters=None, default_sort_field='id', min_select_fields=None,
                 remove_extra_fields=True, distinct=False, rbac_negate=True):
        if filters is None:
            filters = {}
        if min_select_fields is None:
            min_select_fields = {'id'}
        backend = WazuhDBBackend(query_format='global')
        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table='agent', sort=sort, search=search, select=select,
                              filters=filters, fields=Agent.fields, default_sort_field=default_sort_field,
                              default_sort_order='ASC', query=query, backend=backend,
                              min_select_fields=min_select_fields, count=count, get_data=get_data,
                              date_fields={'lastKeepAlive', 'dateAdd'}, extra_fields={'internal_key'},
                              distinct=distinct, rbac_negate=rbac_negate)
        self.remove_extra_fields = remove_extra_fields

    def _filter_date(self, date_filter, filter_db_name):
        WazuhDBQuery._filter_date(self, date_filter, filter_db_name)
        self.query += ' AND id != 0'

    def _sort_query(self, field):
        if field == 'os.version':
            # Order by os major version and os minor version
            return "CAST(os_major AS INTEGER) {0}, CAST(os_minor AS INTEGER) {0}".format(self.sort['order'])
        return WazuhDBQuery._sort_query(self, field)

    def _add_search_to_query(self):
        # since id are stored in database as integers, id searches must be turned into integers to work as expected.
        if self.search:
            del self.fields['id']
            WazuhDBQuery._add_search_to_query(self)
            self.fields['id'] = 'id'
            self.query = self.query[:-1] + ' OR id LIKE :search_id)'
            self.request['search_id'] = int(self.search['value']) if self.search['value'].isdigit() \
                else re.sub(f"[{self.special_characters}]", '_', self.search['value'])

    def _format_data_into_dictionary(self):
        fields_to_nest, non_nested = get_fields_to_nest(self.fields.keys(), ['os'], '.')

        # compute 'status' field, format id with zero padding and remove non-user-requested fields.
        # Also remove, extra fields (internal key and registration IP)
        selected_fields = self.select - self.extra_fields if self.remove_extra_fields else self.select
        selected_fields |= self.min_select_fields
        aux = list()
        for item in self._data:
            # As this is a timestamp, we remove it when its value is 0
            if item.get("disconnection_time") == 0:
                del item["disconnection_time"]
            aux_dict = dict()
            for key, value in item.items():
                if key in selected_fields:
                    aux_dict[key] = format_fields(key, value)

            aux.append(aux_dict)

        self._data = aux

        self._data = [plain_dict_to_nested_dict(d, fields_to_nest, non_nested, ['os'], '.') for d in self._data]

        return super()._format_data_into_dictionary()

    def _parse_legacy_filters(self):
        if 'older_than' in self.legacy_filters and self.legacy_filters['older_than'] != '0s':
            if self.legacy_filters['older_than']:
                self.q = (self.q + ';' if self.q else '') + \
                         "(lastKeepAlive>{0};status!=never_connected,dateAdd>{0};status=never_connected)".format(
                             self.legacy_filters['older_than'])
            del self.legacy_filters['older_than']

        """Parses legacy filters."""
        # some legacy filters can contain multiple values to filter separated by commas. That must split in a list.
        self.legacy_filters.get('older_than', None) == '0s' and self.legacy_filters.pop('older_than')
        legacy_filters_as_list = {
            name: value if isinstance(value, list) else [value] for name, value in self.legacy_filters.items()
        }
        # each filter is represented using a dictionary containing the following fields:
        #   * Value     -> Value to filter by
        #   * Field     -> Field to filter by. Since there can be multiple filters over the same field, a numeric ID
        #                  must be added to the field name.
        #   * Operator  -> Operator to use in the database query. In legacy filters the only available one is =.
        #   * Separator -> Logical operator used to join queries. In legacy filters, the AND operator is used when
        #                  different fields are filtered and the OR operator is used when filtering by the same field
        #                  multiple times.
        #   * Level     -> The level defines the number of parenthesis the query has. In legacy filters, no
        #                  parenthesis are used except when filtering over the same field.

        # Add RBAC filters and remove them from query_filters
        if 'rbac_ids' in legacy_filters_as_list:
            rbac_value = legacy_filters_as_list.pop('rbac_ids')
            operator = 'NOT IN' if self.rbac_negate else 'IN'
        else:
            rbac_value = None

        if rbac_value is not None and (rbac_value or not self.rbac_negate):
            self.query_filters += [{'value': rbac_value,
                                    'field': 'rbac_id',
                                    'operator': operator,
                                    'separator': 'AND',
                                    'level': 0}]

        self.query_filters += [{'value': None if subvalue == "null" else subvalue,
                                'field': '{}${}'.format(name, i),
                                'operator': '=',
                                'separator': 'AND' if len(value) <= 1 or len(value) == i + 1 else 'OR',
                                'level': 0 if i == len(value) - 1 else 1}
                               for name, value in legacy_filters_as_list.items()
                               for i, subvalue in enumerate(value) if not self._pass_filter(subvalue)]

        if self.query_filters:
            # if only traditional filters have been defined, remove last AND from the query.
            self.query_filters[-1]['separator'] = '' if not self.q else 'AND'

    def _process_filter(self, field_name, field_filter, q_filter):
        if field_name == 'group' and q_filter['value'] is not None:
            valid_group_operators = {'=', '!=', '~'}

            if q_filter['operator'] == '=':
                self.query += f"(',' || {self.fields[field_name]} || ',') LIKE :{field_filter}"
                self.request[field_filter] = f"%,{q_filter['value']},%"
            elif q_filter['operator'] == '!=':
                self.query += f"NOT (',' || {self.fields[field_name]} || ',') LIKE :{field_filter}"
                self.request[field_filter] = f"%,{q_filter['value']},%"
            elif q_filter['operator'] == 'LIKE':
                self.query += f"{self.fields[field_name]} LIKE :{field_filter}"
                self.request[field_filter] = f"%{q_filter['value']}%"
            else:
                raise WazuhError(1409, f"Valid operators for 'group' field: {', '.join(valid_group_operators)}. "
                                       f"Used operator: {q_filter['operator']}")
        else:
            WazuhDBQuery._process_filter(self, field_name, field_filter, q_filter)


class WazuhDBQueryGroup(WazuhDBQuery):
    def __init__(self, offset=0, limit=common.database_limit, sort=None, search=None, select=None,
                 get_data=True, query='', filters=None, count=True, default_sort_field='name', min_select_fields=None,
                 remove_extra_fields=True, rbac_negate=True):
        if filters is None:
            filters = {}
        if min_select_fields is None:
            min_select_fields = {'name'}
        backend = WazuhDBBackend(query_format='global')
        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table='`group`', sort=sort, search=search,
                              select=select,
                              filters=filters, fields={'name': 'name'},
                              default_sort_field=default_sort_field, default_sort_order='ASC', query=query,
                              backend=backend, min_select_fields=min_select_fields, count=count, get_data=get_data,
                              rbac_negate=rbac_negate)
        self.remove_extra_fields = remove_extra_fields

    def _add_select_to_query(self):
        pass

    def _add_search_to_query(self):
        super()._add_search_to_query()
        self.query = self.query.replace('WHERE  AND', 'WHERE')
        if 'search' not in self.query:
            self.query = self.query.rstrip('WHERE ')
        self.query += ' GROUP BY name'

    def _default_query(self):
        return "SELECT name, count(id_group) AS count from `group` LEFT JOIN `belongs` on id=id_group WHERE "

    def _get_total_items(self):
        total_items_query = "SELECT COUNT(*) FROM ({}) AS total_groups".format(self.query)
        self.total_items = self.backend.execute(total_items_query, self.request, True)

    def _execute_data_query(self):
        self._data = self.backend.execute(self.query, self.request)

    def _parse_legacy_filters(self):
        if 'older_than' in self.legacy_filters and self.legacy_filters['older_than'] != '0s':
            if self.legacy_filters['older_than']:
                self.q = (self.q + ';' if self.q else '') + \
                         "(lastKeepAlive>{0};status!=never_connected,dateAdd>{0};status=never_connected)".format(
                             self.legacy_filters['older_than'])
            del self.legacy_filters['older_than']

        """Parses legacy filters."""
        # some legacy filters can contain multiple values to filter separated by commas. That must split in a list.
        self.legacy_filters.get('older_than', None) == '0s' and self.legacy_filters.pop('older_than')
        legacy_filters_as_list = {
            name: value if isinstance(value, list) else [value] for name, value in self.legacy_filters.items()
        }
        # each filter is represented using a dictionary containing the following fields:
        #   * Value     -> Value to filter by
        #   * Field     -> Field to filter by. Since there can be multiple filters over the same field, a numeric ID
        #                  must be added to the field name.
        #   * Operator  -> Operator to use in the database query. In legacy filters the only available one is =.
        #   * Separator -> Logical operator used to join queries. In legacy filters, the AND operator is used when
        #                  different fields are filtered and the OR operator is used when filtering by the same field
        #                  multiple times.
        #   * Level     -> The level defines the number of parenthesis the query has. In legacy filters, no
        #                  parenthesis are used except when filtering over the same field.

        # Add RBAC filters and remove them from query_filters
        if 'rbac_ids' in legacy_filters_as_list:
            rbac_value = legacy_filters_as_list.pop('rbac_ids')
            operator = 'NOT IN' if self.rbac_negate else 'IN'
        else:
            rbac_value = None

        if rbac_value is not None:
            self.query_filters += [{'value': rbac_value,
                                    'field': 'rbac_name',
                                    'operator': operator,
                                    'separator': 'AND',
                                    'level': 0}]

        self.query_filters += [{'value': None if subvalue == "null" else subvalue,
                                'field': '{}${}'.format(name, i),
                                'operator': '=',
                                'separator': 'AND' if len(value) <= 1 or len(value) == i + 1 else 'OR',
                                'level': 0 if i == len(value) - 1 else 1}
                               for name, value in legacy_filters_as_list.items()
                               for i, subvalue in enumerate(value) if not self._pass_filter(subvalue)]

        if self.query_filters:
            # if only traditional filters have been defined, remove last AND from the query.
            self.query_filters[-1]['separator'] = '' if not self.q else 'AND'


class WazuhDBQueryDistinctAgents(WazuhDBQueryDistinct, WazuhDBQueryAgents):
    pass


class WazuhDBQueryGroupByAgents(WazuhDBQueryGroupBy, WazuhDBQueryAgents):
    def __init__(self, filter_fields, *args, **kwargs):

        WazuhDBQueryAgents.__init__(self, *args, **kwargs)
        WazuhDBQueryGroupBy.__init__(self, *args, table=self.table, fields=self.fields, filter_fields=filter_fields,
                                     default_sort_field=self.default_sort_field, backend=self.backend, **kwargs)
        self.remove_extra_fields = True

    def _format_data_into_dictionary(self):
        # Add <field>: 'unknown' when filter field is not within the response.
        for result in self._data:
            for field in self.filter_fields['fields']:
                if field not in result.keys():
                    result[field] = 'unknown'

        fields_to_nest, non_nested = get_fields_to_nest(self.fields.keys(), ['os'], '.')

        # compute 'status' field, format id with zero padding and remove non-user-requested fields.
        # Also remove, extra fields (internal key and registration IP)
        selected_fields = self.select - self.extra_fields if self.remove_extra_fields else self.select

        aux = list()
        for item in self._data:
            aux_dict = dict()
            for key, value in item.items():
                if key in selected_fields:
                    aux_dict[key] = format_fields(key, value)

            aux.append(aux_dict)

        self._data = aux
        self._data = [plain_dict_to_nested_dict(d, fields_to_nest, non_nested, ['os'], '.') for d in self._data]

        return WazuhDBQuery._format_data_into_dictionary(self)


class WazuhDBQueryMultigroups(WazuhDBQueryAgents):
    def __init__(self, group_id, query='', *args, **kwargs):
        self.group_id = group_id
        query = 'group={}'.format(group_id) + (';' + query if query else '')
        WazuhDBQueryAgents.__init__(self, query=query, *args, **kwargs)

    def _default_query(self):
        return "SELECT {0} FROM agent a LEFT JOIN belongs b ON a.id = b.id_agent" if self.group_id != "null" \
            else "SELECT {0} FROM agent a"

    def _default_count_query(self):
        return 'COUNT(DISTINCT a.id)'

    def _get_total_items(self):
        self.total_items = self.backend.execute(self.query.format(self._default_count_query()), self.request, True)
        self.query += ' GROUP BY a.id '


class Agent:
    """Wazuh Agent object.
    """
    fields = {'id': 'id', 'name': 'name', 'ip': 'coalesce(ip,register_ip)', 'status': 'connection_status',
              'os.name': 'os_name', 'os.version': 'os_version', 'os.platform': 'os_platform',
              'version': 'version', 'manager': 'manager_host', 'dateAdd': 'date_add',
              'group': '`group`', 'mergedSum': 'merged_sum', 'configSum': 'config_sum',
              'os.codename': 'os_codename', 'os.major': 'os_major', 'os.minor': 'os_minor',
              'os.uname': 'os_uname', 'os.arch': 'os_arch', 'os.build': 'os_build',
              'node_name': 'node_name', 'lastKeepAlive': 'last_keepalive', 'internal_key': 'internal_key',
              'registerIP': 'register_ip', 'disconnection_time': 'disconnection_time'}

    def __init__(self, id=None, name=None, ip=None, key=None, force=None):
        """Initialize an agent.

        `id` when the agent exists.
        `name` and `ip`: generate ID and key automatically.
        `name`, `ip` and `force`: generate ID and key automatically, removing old agent with same name or IP if `force`
            configuration is met.
        `name`, `ip`, `id`, `key` and `force`: insert an agent with an existent ID and key, removing old agent with
            the same name or IP if `force` configuration is met.

        Parameters
        ----------
        id : str
            ID of the agent, if it exists.
        name : str
            Name of the agent.
        ip : str
            IP of the agent.
        key : str
            Key of the agent.
        force : dict
            Authd force parameters.
        """
        self.id = id
        self.name = name
        self.ip = ip
        self.internal_key = key
        self.os = {}
        self.version = None
        self.dateAdd = None
        self.lastKeepAlive = None
        self.status = None
        self.key = None
        self.configSum = None
        self.mergedSum = None
        self.group = None
        self.manager = None
        self.node_name = None
        self.registerIP = ip
        self.disconnection_time = None

        # If the method has only been called with an ID parameter, no new agent should be added.
        # Otherwise, a new agent must be added
        if name is not None and ip is not None:
            self._add(name=name, ip=ip, id=id, key=key, force=force)

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        dictionary = {'id': self.id, 'name': self.name, 'ip': self.ip, 'internal_key': self.internal_key, 'os': self.os,
                      'version': self.version, 'dateAdd': self.dateAdd, 'lastKeepAlive': self.lastKeepAlive,
                      'status': self.status, 'key': self.key, 'configSum': self.configSum, 'mergedSum': self.mergedSum,
                      'group': self.group, 'manager': self.manager, 'node_name': self.node_name,
                      'disconnection_time': self.disconnection_time}

        return dictionary

    def load_info_from_db(self, select=None):
        """Gets attributes of existing agent.
        """
        with WazuhDBQueryAgents(offset=0, limit=None, sort=None, search=None, select=select,
                                query="id={}".format(self.id), count=False, get_data=True,
                                remove_extra_fields=False) as db_query:
            try:
                data = db_query.run()['items'][0]
            except IndexError:
                raise WazuhResourceNotFound(1701)

        list(map(lambda x: setattr(self, x[0], x[1]), data.items()))

    def get_basic_information(self, select=None):
        """Gets public attributes of existing agent.
        """
        self.load_info_from_db(select)
        fields = set(self.fields.keys()) & set(select) if select is not None \
            else set(self.fields.keys()) - {'internal_key'}
        return {field: getattr(self, field) for field in map(lambda x: x.split('.')[0], fields) if getattr(self, field)}

    def compute_key(self):
        str_key = "{0} {1} {2} {3}".format(self.id, self.name, self.registerIP, self.internal_key)
        return b64encode(str_key.encode()).decode()

    def get_key(self):
        """Gets agent key.

        :return: Agent key.
        """
        self.load_info_from_db()
        if self.id != "000":
            self.key = self.compute_key()
        else:
            raise WazuhError(1703)

        return self.key

    def reconnect(self, wq: WazuhQueue) -> str:
        """Force reconnect to the manager.

        Parameters
        ----------
        wq : WazuhQueue
            WazuhQueue used for the active response message.

        Raises
        ------
        WazuhError(1750)
            If the agent has active response disabled.
        WazuhError(1707)
            If the agent to be reconnected is not active.

        Returns
        -------
        str
            Message generated by Wazuh.
        """
        # Check if agent is active
        self.get_basic_information()
        if self.status.lower() != 'active':
            raise WazuhError(1707)

        # Send force reconnect message to the WazuhQueue
        ret_msg = wq.send_msg_to_agent(WazuhQueue.HC_FORCE_RECONNECT, self.id)

        return ret_msg

    def remove(self, purge: bool = False) -> str:
        """Delete the agent.

        Parameters
        ----------
        purge : boolean
            Remove key from store.

        Raises
        ------
        WazuhError(1726)
            Authd is not running.

        WazuhInternalError(1757)
            Unhandled exception.

        Returns
        -------
        data : str
            Message generated by Wazuh.
        """

        manager_status = get_manager_status(cache=True)
        is_authd_running = 'wazuh-authd' in manager_status and manager_status['wazuh-authd'] == 'running'

        if not is_authd_running:
            raise WazuhError(1726)

        try:
            data = self._remove_authd(purge)

            return data
        except WazuhException as e:
            raise e
        except Exception as e:
            raise WazuhInternalError(1757, extra_message=str(e))

    def _remove_authd(self, purge=False):
        """Deletes the agent.

        :param purge: Delete definitely from key store.
        :return: Message.
        """
        msg = {"function": "remove", "arguments": {"id": str(self.id).zfill(3), "purge": purge}}

        authd_socket = WazuhSocketJSON(common.AUTHD_SOCKET)
        authd_socket.send(msg)
        data = authd_socket.receive()
        authd_socket.close()

        return data

    def _add(self, name, ip, id=None, key=None, force=None):
        """Add an agent to Wazuh.
        2 uses:
            - name and ip [force]: Add an agent like manage_agents (generate id and key).
            - name, ip, id, key [force]: Insert an agent with an existing id and key.

        Parameters
        ----------
        name : str
            Name of the new agent.
        ip : str
            IP of the new agent. It can be an IP, IP/NET or ANY.
        id : str
            ID of the new agent.
        key : str
            Key of the new agent.
        force : dict
            Remove old agents with same name or IP if conditions are met.

        Raises
        ------
        WazuhError(1706)
            If there is an agent with the same IP or the IP is invalid.
        WazuhInternalError(1725)
            If there was an error registering a new agent.
        WazuhError(1726)
            If authd is not running.

        Returns
        -------
        Agent ID.
        """
        ip = ip.lower()
        if ip != 'any':
            if ip.find('/') > 0:
                try:
                    ipaddress.ip_network(ip)
                except Exception:
                    raise WazuhError(1706, extra_message=ip)
            else:
                try:
                    ipaddress.ip_address(ip)
                except Exception:
                    raise WazuhError(1706, extra_message=ip)

        manager_status = get_manager_status()
        is_authd_running = 'wazuh-authd' in manager_status and manager_status['wazuh-authd'] == 'running'

        if not is_authd_running:
            raise WazuhError(1726)

        try:
            self._add_authd(name, ip, id, key, force)
        except WazuhException as e:
            raise e
        except Exception as e:
            raise WazuhInternalError(1725, extra_message=str(e))

    def _add_authd(self, name, ip, id=None, key=None, force=None):
        """Add an agent to Wazuh using authd.
        2 uses:
            - name and ip [force]: Add an agent like manage_agents (generate id and key).
            - name, ip, id, key [force]: Insert an agent with an existing id and key.

        Parameters
        ----------
        name : str
            Name of the new agent.
        ip : str
            IP of the new agent. It can be an IP, IP/NET or ANY.
        id : str
            ID of the new agent.
        key : str
            Key of the new agent.
        force : dict
            Remove old agents with same name or IP if conditions are met.

        Raises
        ------
        WazuhError(1705)
            If there is an agent with the same name
        WazuhError(1706)
            If there is an agent with the same IP or the IP is invalid.
        WazuhError(1708)
            If there is an agent with the same ID.
        WazuhError(1709)
            If the key size is too short.

        Returns
        -------
        Agent ID.
        """
        # Check arguments
        if id:
            id = id.zfill(3)

        if key and len(key) < 64:
            raise WazuhError(1709)

        msg = ""
        if name and ip:
            msg = {"function": "add", "arguments": {"name": name, "ip": ip}}

            if force is not None:
                # This force field must always be present
                force.update({"key_mismatch": True})
                msg["arguments"]["force"] = force

            if id and key:
                msg["arguments"].update({"id": id, "key": key})

        try:
            authd_socket = WazuhSocketJSON(common.AUTHD_SOCKET)
            authd_socket.send(msg)
            data = authd_socket.receive()
            authd_socket.close()
        except WazuhException as e:
            if e.code == 9008:
                raise WazuhError(1705, extra_message=name)
            elif e.code == 9007:
                raise WazuhError(1706, extra_message=ip)
            elif e.code == 9012:
                raise WazuhError(1708, extra_message=id)
            raise e

        self.id = data['id']
        self.internal_key = data['key']
        self.key = self.compute_key()

    @staticmethod
    def delete_single_group(group_id):
        """Delete a group

        :param group_id: Group ID.
        :return: Confirmation message.
        """
        # Delete group directory (move it to a backup)
        group_path = path.join(common.shared_path, group_id)
        if path.exists(group_path):
            rmtree(group_path)

        msg = "Group '{0}' deleted.".format(group_id)

        return {'message': msg}

    def get_agent_os_name(self):
        """Returns a string with an agent's os name
        """
        query = WazuhDBQueryAgents(select=['os.name'], filters={'id': [self.id]})

        try:
            return query.run()['items'][0]['os'].get('name', 'null')
        except KeyError:
            return 'null'

    @staticmethod
    def get_agents_overview(offset=0, limit=common.database_limit, sort=None, search=None, select=None,
                            filters=None, q=""):
        """Gets a list of available agents with basic attributes.

        Parameters
        ----------
        offset : int
            First item to return.
        limit : int
            Maximum number of items to return.
        sort : str
            Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        search : str
            Looks for items with the specified string. Format: {"fields": ["field1","field2"]}.
        select : str
            Select fields to return. Format: {"fields":["field1","field2"]}.
        filters : dict
            Defines required field filters.
        q : str
            Defines query to filter in DB.

        Returns
        -------
        Information gathered from the database query
        """
        pfilters = get_rbac_filters(system_resources=get_agents_info(), permitted_resources=filters.pop('id'),
                                    filters=filters) if filters and 'id' in filters else {'filters': filters}
        db_query = WazuhDBQueryAgents(offset=offset, limit=limit, sort=sort, search=search, select=select,
                                      query=q, **pfilters)
        data = db_query.run()

        return data

    @staticmethod
    def add_group_to_agent(group_id, agent_id, replace=False, replace_list=None):
        """Add an existing group to an agent.
        
        Parameters
        ----------
        group_id: str
            Name of the group.
        agent_id: str
            ID of the agent.
        replace: bool
            Whether to append new group to current agent's group or replace it.
        replace_list: bool
            List of group names that can be replaced.

        Returns
        -------
        str
            Confirmation message with agent and group IDs.
        """
        if replace_list is None:
            replace_list = []

        # Get agent's group
        try:
            agent_multigroups = Agent.get_agent_groups(agent_id)
        except Exception as e:
            raise WazuhInternalError(1005, extra_message=str(e))
        agent_groups = set(agent_multigroups)

        if replace:
            if not agent_groups.issubset(set(replace_list)):
                raise WazuhError(1752)
        else:
            # Check if the group already belongs to the agent
            if group_id in agent_groups:
                raise WazuhError(1751)

        # Check multigroup limit
        if len(agent_groups) >= common.max_groups_per_multigroup:
            raise WazuhError(1737)

        # Update group file
        Agent.set_agent_group_relationship(agent_id, group_id, override=replace)

        return f"Agent {agent_id} assigned to {group_id}"

    @staticmethod
    def check_if_delete_agent(id, seconds):
        """Check if we should remove an agent: if time from last connection is greater thant <seconds>.

        :param id: id of the new agent.
        :param seconds: Number of seconds.
        :return: True if time from last connection is greater thant <seconds>.
        """
        remove_agent = False

        # Always return true for 0 seconds to prevent any possible races
        if seconds == 0:
            remove_agent = True
        else:
            agent_info = Agent(id=id).get_basic_information()
            if 'lastKeepAlive' in agent_info:
                if agent_info['lastKeepAlive'] == 0:
                    remove_agent = True
                else:
                    if isinstance(agent_info['lastKeepAlive'], datetime):
                        last_date = agent_info['lastKeepAlive']
                    else:
                        last_date = datetime.strptime(agent_info['lastKeepAlive'], '%Y-%m-%d %H:%M:%S')
                    difference = (datetime.utcnow() - last_date).total_seconds()
                    if difference >= seconds:
                        remove_agent = True

        return remove_agent

    @staticmethod
    def group_exists(group_id):
        """Checks if the group exists

        :param group_id: Group ID.
        :return: True if group exists, False otherwise
        """
        # Input Validation of group_id
        if not InputValidator().group(group_id):
            raise WazuhError(1722)

        if path.exists(path.join(common.shared_path, group_id)):
            return True
        else:
            return False

    @staticmethod
    def get_agent_groups(agent_id):
        """Return all agent's groups.

        Parameters
        ----------
        agent_id: str
            Agent ID.

        Returns
        -------
        list
            List of group IDs.
        """
        wdb = WazuhDBConnection()
        try:
            _, payload = wdb.run_wdb_command(f'global select-group-belong {agent_id}')
            return json.loads(payload)
        finally:
            wdb.close()

    @staticmethod
    def set_agent_group_relationship(agent_id, group_id, remove=False, override=False):
        if remove:
            mode = 'remove'
        else:
            mode = 'append' if not override else 'override'

        command = f'global set-agent-groups {{"mode":"{mode}","sync_status":"syncreq","data":[{{"id":{agent_id},' \
                  f'"groups": ["{group_id}"]}}]}}'

        wdb = WazuhDBConnection()
        try:
            wdb.run_wdb_command(command)
        except Exception as e:
            raise WazuhInternalError(1005, extra_message=str(e))
        finally:
            wdb.close()

    @staticmethod
    def unset_single_group_agent(agent_id, group_id, force=False):
        """Unset the agent group. If agent has multigroups, it will preserve all previous groups except the last one.
        
        Parameters
        ----------
        agent_id: str
            Agent ID.
        group_id: str
            Group ID.
        force: bool
            Do not check if agent or group exists.

        Returns
        -------
        str
            Confirmation message.
        """
        if not force:
            # Check if agent exists, it is not 000 and the group exists
            Agent(agent_id).get_basic_information()

            if agent_id == "000":
                raise WazuhError(1703)

            if not Agent.group_exists(group_id):
                raise WazuhResourceNotFound(1710)

        # Get agent's group
        group_list = set(Agent.get_agent_groups(agent_id))
        set_default = False

        # Check agent belongs to group group_id
        if group_id not in group_list:
            raise WazuhError(1734)
        elif len(group_list) == 1:
            if group_id == 'default':
                raise WazuhError(1745)
            else:
                set_default = True

        # Update group file
        # TODO core team is implementing a fix to make this whole process atomic. Default addition is failing too
        Agent.set_agent_group_relationship(agent_id, group_id, remove=True)
        set_default and Agent.set_agent_group_relationship(agent_id, 'default')

        return f"Agent '{agent_id}' removed from '{group_id}'." + (" Agent reassigned to group default."
                                                                   if set_default else "")

    def getconfig(self, component: str = '', config: str = '', agent_version: str = '') -> dict:
        """Read agent's loaded configuration.

        Parameters
        ----------
        component : str
            Selected component of the agent configuration.
        config : str
            Agent's active configuration to get.
        agent_version : str
            Agent version to compare with the required version. The format is vX.Y.Z or Wazuh vX.Y.Z.

        Raises
        ------
        WazuhError(1735)
            The agent version is older than the minimum required version.

        Returns
        -------
        dict
            Agent's active configuration.
        """
        if WazuhVersion(agent_version) < WazuhVersion(common.ACTIVE_CONFIG_VERSION):
            raise WazuhInternalError(1735, extra_message=f"Minimum required version is {common.ACTIVE_CONFIG_VERSION}")

        return configuration.get_active_configuration(self.id, component, config)

    def get_stats(self, component):
        """Read the agent's component stats.

        Parameters
        ----------
        component : string
            Name of the component to get stats from.

        Returns
        -------
        Dict
            Object with component's stats.
        """
        # Check if agent version is compatible with this feature
        self.load_info_from_db()
        if self.version is None:
            raise WazuhInternalError(1015)
        agent_version = WazuhVersion(self.version.split(" ")[1])
        required_version = WazuhVersion(AGENT_COMPONENT_STATS_REQUIRED_VERSION.get(component))
        if agent_version < required_version:
            raise WazuhInternalError(1735, extra_message="Minimum required version is " + str(required_version))

        return stats.get_daemons_stats_from_socket(self.id, component)


def format_fields(field_name, value):
    if field_name == 'id':
        return str(value).zfill(3)
    elif field_name == 'group':
        return value.split(',')
    elif field_name in ['dateAdd', 'lastKeepAlive', 'disconnection_time']:
        return datetime.utcfromtimestamp(value) if not isinstance(value, str) else value
    else:
        return value


def send_restart_command(agent_id: str = '', agent_version: str = '', wq: WazuhQueue = None) -> str:
    """Send restart command to an agent.

    Parameters
    ----------
    agent_id : str
        ID specifying the agent where the restart command will be sent to
    agent_version : str
        Agent version to compare with the required version. The format is vX.Y.Z.
    wq : WazuhQueue
        WazuhQueue used for the active response messages.

    Returns
    -------
    str
        Message generated by Wazuh.
    """
    # If the Wazuh agent version is newer or equal to the AR legacy version,
    # the message sent will have JSON format
    if WazuhVersion(agent_version) >= WazuhVersion(common.AR_LEGACY_VERSION):
        ret_msg = wq.send_msg_to_agent(WazuhQueue.RESTART_AGENTS_JSON, agent_id)
    else:
        ret_msg = wq.send_msg_to_agent(WazuhQueue.RESTART_AGENTS, agent_id)

    return ret_msg


@common.context_cached('system_agents')
def get_agents_info():
    """Get all agent IDs in the system."""
    with open(common.client_keys, 'r') as f:
        file_content = f.read()

    result = set(agent_regex.findall(file_content))
    result.add('000')

    return result


@common.context_cached('system_groups')
def get_groups():
    """Get all groups in the system

    :return: List of group names
    """
    groups = set()
    for shared_file in listdir(common.shared_path):
        path.isdir(path.join(common.shared_path, shared_file)) and groups.add(shared_file)

    return groups


@common.context_cached('system_expanded_groups')
def expand_group(group_name):
    """Expand a certain group or all (*) of them.
    
    Parameters
    ----------
    group_name: str
        Name of the group to be expanded.

    Returns
    -------
    set
        Set of agent IDs.
    """
    agents_ids = set()
    if group_name == '*':
        # for file in listdir(common.groups_path):
        #     try:
        #         if path.getsize(path.join(common.groups_path, file)) > 0:
        #             agents_ids.add(file)
        #     except FileNotFoundError:
        #         # Agent group removed while running through listed dir
        #         pass
        last_id = 0
        wdb_conn = WazuhDBConnection()
        try:
            while True:
                command = 'global sync-agent-groups-get {"last_id":' f'{last_id}' ', "condition":"all"}'
                status, payload = wdb_conn.run_wdb_command(command)
                for agent in json.loads(payload)[0]['data']:
                    agents_ids.add(str(agent['id']).zfill(3))

                if status == 'ok':
                    break
                else:
                    last_id += 1
        finally:
            wdb_conn.close()

    else:
        # TODO new wdb command to expand single groups
        for file in listdir(common.groups_path):
            try:
                with open(path.join(common.groups_path, file), 'r') as f:
                    file_content = f.readlines()
                len(file_content) == 1 and group_name in file_content[0].strip().split(',') and agents_ids.add(file)
            except FileNotFoundError:
                # Agent group removed while running through listed dir
                pass

    return agents_ids & get_agents_info()


@lru_cache()
def get_manager_name():
    """This function read the manager name from global.db"""
    wdb_conn = WazuhDBConnection()
    manager_name = wdb_conn.execute("global sql SELECT name FROM agent WHERE (id = 0)")[0]['name']
    wdb_conn.close()

    return manager_name


def get_rbac_filters(system_resources=None, permitted_resources=None, filters=None):
    """This function calculate the list of allowed or denied depending on the list size

    Parameters
    ----------
    system_resources : set
        System resources for the current request
    permitted_resources : list
        Resources granted by RBAC
    filters : dict
        Dictionary with additional filters for the current request

    Returns
    -------
    Dictionary with the original filters plus those added by RBAC
    """
    if not filters:
        filters = dict()
    non_permitted_resources = system_resources - set(permitted_resources)

    if len(permitted_resources) < len(non_permitted_resources):
        filters['rbac_ids'] = permitted_resources
        negate = False
    else:
        filters['rbac_ids'] = list(non_permitted_resources)
        negate = True

    return {'filters': filters, 'rbac_negate': negate}


def core_upgrade_agents(agents_chunk, command='upgrade_result', wpk_repo=None, version=None,
                        force=False, use_http=False, file_path=None, installer=None, get_result=False):
    """Send command to upgrade module / task module

    Parameters
    ----------
    agents_chunk : list
        List of agents ID's.
    command : str
        Command sent to the socket.
    wpk_repo : str
        URL for WPK download.
    version : str
        Version to upgrade to.
    force : bool
        force the update even if it is a downgrade.
    use_http : bool
        False for HTTPS protocol, True for HTTP protocol.
    file_path : str
        Path to the installation file.
    installer : str
        Selected installer.
    get_result : bool
        Get the result of an update (True -> Task module), Create new upgrade task (False -> Upgrade module)

    Returns
    -------
    Message received from the socket (Task module or Upgrade module)
    """
    msg = create_wazuh_socket_message(origin={'module': 'api'},
                                      command=command,
                                      parameters={
                                          'agents': agents_chunk,
                                          'version': version,
                                          'force_upgrade': force,
                                          'use_http': use_http,
                                          'wpk_repo': wpk_repo,
                                          'file_path': file_path,
                                          'installer': installer
                                      } if not get_result else {'agents': agents_chunk})

    msg['parameters'] = {k: v for k, v in msg['parameters'].items() if v is not None}

    # Send upgrading command
    s = WazuhSocket(common.UPGRADE_SOCKET)
    s.send(dumps(msg).encode())

    # Receive upgrade information from socket
    data = loads(s.receive().decode())
    s.close()
    [agent_info.update((k, datetime.strptime(v, "%Y/%m/%d %H:%M:%S").strftime(date_format))
                       for k, v in agent_info.items() if k in {'create_time', 'update_time'})
     for agent_info in data['data']]

    return data
