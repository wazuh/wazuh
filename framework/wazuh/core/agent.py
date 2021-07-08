# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

import fcntl
import hashlib
import ipaddress
import mmap
import re
import tempfile
import threading
from base64 import b64encode
from datetime import date, datetime
from functools import lru_cache
from json import dumps, loads
from os import chown, chmod, makedirs, urandom, stat, remove
from os import listdir, path
from platform import platform
from shutil import rmtree
from time import time

import api.configuration as aconf
from wazuh.core import common, configuration, stats
from wazuh.core.InputValidator import InputValidator
from wazuh.core.cluster.utils import get_manager_status
from wazuh.core.common import AGENT_COMPONENT_STATS_REQUIRED_VERSION
from wazuh.core.exception import WazuhException, WazuhError, WazuhInternalError, WazuhResourceNotFound
from wazuh.core.utils import chmod_r, WazuhVersion, plain_dict_to_nested_dict, get_fields_to_nest, WazuhDBQuery, \
    WazuhDBQueryDistinct, WazuhDBQueryGroupBy, WazuhDBBackend, safe_move
from wazuh.core.wazuh_queue import WazuhQueue
from wazuh.core.wazuh_socket import WazuhSocket, WazuhSocketJSON
from wazuh.core.wdb import WazuhDBConnection

detect_wrong_lines = re.compile(r'(.+ .+ .+ .+)')
detect_valid_lines = re.compile(r'^(\d+) (.*) (.*) (.*)', re.MULTILINE)

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
                else self.search['value']

    def _format_data_into_dictionary(self):
        fields_to_nest, non_nested = get_fields_to_nest(self.fields.keys(), ['os'], '.')

        # compute 'status' field, format id with zero padding and remove non-user-requested fields.
        # Also remove, extra fields (internal key and registration IP)
        selected_fields = self.select - self.extra_fields if self.remove_extra_fields else self.select
        selected_fields |= self.min_select_fields
        aux = list()
        for item in self._data:
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
              'registerIP': 'register_ip'}

    def __init__(self, id=None, name=None, ip=None, key=None, force=-1, use_only_authd=False):
        """Initialize an agent.

        :param: id: When the agent exists
        :param: name and ip: Add an agent (generate id and key automatically)
        :param: name, ip and force: Add an agent (generate id and key automatically), removing old agent with same IP if
        disconnected since <force> seconds.
        :param: name, ip, id, key: Insert an agent with an existent id and key
        :param: name, ip, id, key, force: Insert an agent with an existent id and key, removing old agent with same IP
         if disconnected since <force> seconds.
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

        # If the method has only been called with an ID parameter, no new agent should be added.
        # Otherwise, a new agent must be added
        if name is not None and ip is not None:
            self._add(name=name, ip=ip, id=id, key=key, force=force, use_only_authd=use_only_authd)

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        dictionary = {'id': self.id, 'name': self.name, 'ip': self.ip, 'internal_key': self.internal_key, 'os': self.os,
                      'version': self.version, 'dateAdd': self.dateAdd, 'lastKeepAlive': self.lastKeepAlive,
                      'status': self.status, 'key': self.key, 'configSum': self.configSum, 'mergedSum': self.mergedSum,
                      'group': self.group, 'manager': self.manager, 'node_name': self.node_name}

        return dictionary

    @staticmethod
    def _acquire_client_keys_lock(timeout=None):
        timeout = aconf.api_conf['intervals']['request_timeout'] - 1 if not timeout else timeout
        if mutex.acquire(timeout=timeout):
            global lock_file
            lock_file = open("{}/var/run/.api_lock".format(common.wazuh_path), 'a+')
            fcntl.lockf(lock_file, fcntl.LOCK_EX)
            global lock_acquired
            lock_acquired = True
            return True

        return False

    @staticmethod
    def _release_client_keys_lock():
        global lock_file
        fcntl.lockf(lock_file, fcntl.LOCK_UN)
        lock_file is not None and lock_file.close()
        lock_file = None
        global lock_acquired
        try:
            mutex.release()
        except RuntimeError:
            raise WazuhInternalError(1758)
        finally:
            lock_acquired = False

    def load_info_from_db(self, select=None):
        """Gets attributes of existing agent.
        """
        db_query = WazuhDBQueryAgents(offset=0, limit=None, sort=None, search=None, select=select,
                                      query="id={}".format(self.id), count=False, get_data=True,
                                      remove_extra_fields=False)
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
        WazuhError(1757)
            If the agent to be reconnected is not active.

        Returns
        -------
        str
            Message generated by Wazuh.
        """
        # Check if agent is active
        self.get_basic_information()
        if self.status.lower() != 'active':
            raise WazuhError(1757)

        # Send force reconnect message to the WazuhQueue
        ret_msg = wq.send_msg_to_agent(WazuhQueue.HC_FORCE_RECONNECT, self.id)

        return ret_msg


    def remove(self, backup=False, purge=False, use_only_authd=False):
        """Delete the agent.

        :param backup: Create backup before removing the agent.
        :param purge: Delete definitely from key store.
        :param use_only_authd: Force the use of authd when adding and removing agents.
        :return: Message.
        """

        manager_status = get_manager_status(cache=True)
        is_authd_running = 'wazuh-authd' in manager_status and manager_status['wazuh-authd'] == 'running'

        if use_only_authd and not is_authd_running:
            raise WazuhError(1726)

        try:
            if not is_authd_running:
                data = self._remove_manual(backup, purge)
            else:
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

    def _remove_manual(self, backup=False, purge=False):
        """Deletes the agent.

        :param backup: Create backup before removing the agent.
        :param purge: Delete definitely from key store.
        :return: Message.
        """
        # Check if agent exists
        self.load_info_from_db()

        client_keys_entries = []

        # Try to acquire client keys lock
        if not Agent._acquire_client_keys_lock():
            raise WazuhInternalError(1759)

        try:
            agent_found = False
            with open(common.client_keys) as f_k:
                for line in f_k.readlines():
                    line = line.rstrip()
                    if line:
                        if not line.startswith('#') and not line.startswith(' '):
                            try:
                                entry_id, entry_name, entry_ip, entry_key = line.split(' ')
                            except ValueError:
                                # Bad entries will be ignored and not rewritten to the new file
                                continue
                        else:
                            # Ignore void entries, but preserve them
                            client_keys_entries.append(line)
                            continue
                        if self.id == entry_id and not (entry_name.startswith('#') or entry_name.startswith('!')):
                            # If not purging then create a void entry
                            agent_found = True
                            if not purge:
                                client_keys_entries.append(
                                    '{0} !{1} {2} {3}'.format(entry_id, entry_name, entry_ip, entry_key))
                        else:
                            client_keys_entries.append(line)

            if not agent_found:
                raise WazuhResourceNotFound(1701, extra_message=self.id)

            self.delete_agent_files(self.id, self.name, self.registerIP, backup=backup)

            # Write temporary client.keys file
            handle, output = tempfile.mkstemp(prefix=common.client_keys, suffix=".tmp")
            with open(handle, 'a') as f_kt:
                client_keys_entries.append('')
                f_kt.writelines('\n'.join(client_keys_entries))

            # Overwrite client.keys
            f_keys_st = stat(common.client_keys)
            safe_move(output, common.client_keys, permissions=f_keys_st.st_mode)
        except WazuhResourceNotFound as e:
            raise e
        except Exception as e:
            raise WazuhInternalError(1746, extra_message=str(e))
        finally:
            Agent._release_client_keys_lock()

        return 'Agent was successfully deleted'

    @staticmethod
    def delete_agent_files(agent_id, agent_name, agent_register_ip, backup=True):
        # Tell wazuh-db to delete agent database
        wdb_backend_conn = WazuhDBBackend(agent_id).connect_to_db()
        wdb_backend_conn.delete_agents_db([agent_id])

        # Remove agent from groups
        try:
            wdb_conn = WazuhDBConnection()
            wdb_conn.run_wdb_command(f'global sql DELETE FROM belongs WHERE id_agent = {agent_id}')
        except Exception as e:
            raise WazuhInternalError(1747, extra_message=str(e))

        # Clean up agent files
        try:
            # Remove rid file
            rids_file = path.join(common.wazuh_path, 'queue/rids', agent_id)
            if path.exists(rids_file):
                remove(rids_file)

            if backup:
                # Create backup directory
                # /var/ossec/backup/agents/yyyy/Mon/dd/id-name-ip[tag]
                date_part = date.today().strftime('%Y/%b/%d')
                main_agent_backup_dir = path.join(common.backup_path,
                                                  f'agents/{date_part}/{agent_id}-{agent_name}-{agent_register_ip}')
                agent_backup_dir = main_agent_backup_dir

                not_agent_dir = True
                i = 0
                while not_agent_dir:
                    if path.exists(agent_backup_dir):
                        i += 1
                        agent_backup_dir = '{0}-{1}'.format(main_agent_backup_dir, str(i).zfill(3))
                    else:
                        makedirs(agent_backup_dir)
                        chmod_r(agent_backup_dir, 0o750)
                        not_agent_dir = False
            else:
                agent_backup_dir = ''

            # Move agent file
            agent_files = [
                ('{0}/queue/rootcheck/({1}) {2}->rootcheck'.format(common.wazuh_path, agent_name, agent_register_ip),
                 '{0}/rootcheck'.format(agent_backup_dir)),
                ('{0}/queue/agent-groups/{1}'.format(common.wazuh_path, agent_id),
                 '{0}/agent-group'.format(agent_backup_dir)),
                ('{}/var/db/agents/{}-{}.db'.format(common.wazuh_path, agent_name, agent_id),
                 '{}/var_db'.format(agent_backup_dir)),
                ('{}/queue/diff/{}'.format(common.wazuh_path, agent_name), '{}/diff'.format(agent_backup_dir))
            ]

            for agent_file, backup_file in agent_files:
                if path.exists(agent_file):
                    if not backup:
                        if path.isdir(agent_file):
                            rmtree(agent_file)
                        else:
                            remove(agent_file)
                    elif not path.exists(backup_file):
                        safe_move(agent_file, backup_file, permissions=0o660)
        except Exception as e:
            raise WazuhInternalError(1748, extra_message=str(e))

    def _add(self, name, ip, id=None, key=None, force=-1, use_only_authd=False):
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
        force : int
            Remove old agents with same IP if disconnected since <force> seconds.
        use_only_authd : bool
            Force the use of authd when adding and removing agents.

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

        if use_only_authd and not is_authd_running:
            raise WazuhError(1726)

        try:
            if not is_authd_running:
                self._add_manual(name, ip, id, key, force)
            else:
                self._add_authd(name, ip, id, key, force)
        except WazuhException as e:
            raise e
        except Exception as e:
            raise WazuhInternalError(1725, extra_message=str(e))

    def _add_authd(self, name, ip, id=None, key=None, force=-1):
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
        force : int
            Remove old agents with same IP if disconnected since <force> seconds.

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

        force = force if type(force) == int else int(force)

        msg = ""
        if name and ip:
            if id and key:
                msg = {"function": "add", "arguments": {"name": name, "ip": ip, "id": id, "key": key, "force": force}}
            else:
                msg = {"function": "add", "arguments": {"name": name, "ip": ip, "force": force}}

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

    def _add_manual(self, name, ip, id=None, key=None, force=-1):
        """Add an agent to Wazuh manually.
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
        force : int
            Remove old agents with same IP if disconnected since <force> seconds.

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
            agent_id = id.zfill(3)
        else:
            agent_id = None

        if key:
            if len(key) < 64:
                raise WazuhError(1709)
            else:
                agent_key = key
        else:
            hash1 = hashlib.md5("{0}{1}{2}".format(int(time()), name, platform()).encode())
            hash1.update(urandom(128))
            hash2 = hashlib.md5(f"{ip}{agent_id}".encode())
            agent_key = hash1.hexdigest() + hash2.hexdigest()

        force = int(force)

        # Check manager name
        manager_name = get_manager_name()

        if name == manager_name:
            raise WazuhError(1705, extra_message=f"Agent 000 (manager) has name {name}")

        # Never allow duplication or replacement of an agent id. Check before running through the client.keys to avoid
        # deleting an entry with duplicate name or ip and then find out that the id was already present
        if agent_id in get_agents_info():
            raise WazuhError(1708, agent_id)

        # Check if ip or name exist in client.keys
        last_id = 0

        # Try to acquire client keys lock
        if not Agent._acquire_client_keys_lock():
            raise WazuhInternalError(1759)

        try:
            with open(common.client_keys) as f_k:
                with mmap.mmap(f_k.fileno(), length=0, access=mmap.ACCESS_READ) as file_client:
                    content = file_client.read().decode()
                    # Remove lines that do not follow the general scheme
                    client_keys_entries = detect_wrong_lines.findall(content)

                    # Update last_id with highest value
                    if not agent_id:
                        try:
                            last_id = max(int(line[0]) for line in detect_valid_lines.findall(content))
                        except ValueError:
                            last_id = 0

                    # Detect entries with duplicate name or ip
                    if (name in content and f'!{name}' not in content) or (ip != 'any' and ip in content):
                        # Regular expression that will help us to search for the target line
                        regex = rf'.* {name} .* .*|.* {name} {ip} .*' if name in content else rf'.* .* {ip} .*'

                        for index, line in enumerate(client_keys_entries):
                            agent_match = re.match(regex, line.rstrip())

                            # Line found
                            if agent_match:
                                entry_id, entry_name, entry_ip, entry_key = agent_match[0].split(' ')

                                # If force is non-negative then we check to remove the agent using value of force as
                                # the max age in seconds
                                if force >= 0 and Agent.check_if_delete_agent(entry_id, force):
                                    self.delete_agent_files(entry_id, entry_name, entry_ip, backup=True)
                                    # We add a void entry
                                    client_keys_entries[index] = f'{entry_id} !{entry_name} {entry_ip} {entry_key}'
                                else:
                                    # If force is negative or the agent is not older than the max age we raise
                                    # an error based on the duplicate field.
                                    if name == entry_name:
                                        raise WazuhError(1705, extra_message=name)
                                    else:
                                        raise WazuhError(1706, extra_message=ip)

            # If id not specified then create a new id 1 greater than the last id created.
            if not agent_id:
                agent_id = str(last_id + 1).zfill(3)

            # Write temporary client.keys file
            handle, output = tempfile.mkstemp(prefix=common.client_keys, suffix=".tmp")
            with open(handle, 'a') as f_kt:
                client_keys_entries.append('')
                f_kt.writelines('\n'.join(client_keys_entries))
                f_kt.write('{0} {1} {2} {3}\n'.format(agent_id, name, ip, agent_key))

            # Overwrite client.keys
            f_keys_st = stat(common.client_keys)
            safe_move(output, common.client_keys, permissions=f_keys_st.st_mode)
        finally:
            Agent._release_client_keys_lock()
        self.id = agent_id
        self.internal_key = agent_key
        self.key = self.compute_key()

    @staticmethod
    def delete_single_group(group_id):
        """Delete a group

        :param group_id: Group ID.
        :return: Confirmation message.
        """
        # Delete group directory (move it to a backup)
        group_path = path.join(common.shared_path, group_id)
        group_backup = path.join(common.backup_path, 'groups', "{0}_{1}".format(group_id, int(time())))
        if path.exists(group_path):
            safe_move(group_path, group_backup, permissions=0o660)

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

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
        :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
        :param filters: Defines required field filters.
        Format: {"field1":"value1", "field2":["value2","value3"]}
        :param q: Defines query to filter in DB.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        db_query = WazuhDBQueryAgents(offset=offset, limit=limit, sort=sort, search=search, select=select,
                                      filters=filters, query=q)
        data = db_query.run()

        return data

    @staticmethod
    def add_group_to_agent(group_id, agent_id, force=False, replace=False, replace_list=None):
        """Adds an existing group to an agent

        :param group_id: name of the group.
        :param agent_id: ID of the agent.
        :param force: Do not check if agent exists
        :param replace: Whether to append new group to current agent's group or replace it.
        :param replace_list: List of Group names that can be replaced
        :return: Agent ID.
        """
        agent = Agent(agent_id)
        if replace_list is None:
            replace_list = []
        if not force:
            # Check if agent exists, it is not 000 and the group exists
            if agent_id == "000":
                raise WazuhError(1703)

            if not Agent.group_exists(group_id):
                raise WazuhResourceNotFound(1710)

        # Get agent's group
        group_path = path.join(common.groups_path, agent_id)
        try:
            with open(group_path) as f:
                multigroup_name = f.read().strip()
        except Exception as e:
            # Check if agent is never_connected.
            agent.load_info_from_db()
            if agent.status == 'never_connected':
                raise WazuhError(1753)
            raise WazuhInternalError(1005, extra_message=str(e))
        agent_groups = set(multigroup_name.split(','))

        if replace:
            if agent_groups.issubset(set(replace_list)):
                multigroup_name = group_id
            else:
                raise WazuhError(1752)
        else:
            # Check if the group already belongs to the agent
            if group_id in agent_groups:
                raise WazuhError(1751)

            multigroup_name = f'{multigroup_name}{"," if multigroup_name else ""}{group_id}'

        # Check multigroup limit
        if len(agent_groups) > common.max_groups_per_multigroup:
            raise WazuhError(1737)

        # Update group file
        Agent.set_agent_group_file(agent_id, multigroup_name)

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
    def get_agents_group_file(agent_id):
        group_path = path.join(common.groups_path, agent_id)
        if path.exists(group_path):
            with open(group_path) as f:
                group_name = f.read().strip()
            return group_name
        else:
            return ''

    @staticmethod
    def set_agent_group_file(agent_id, group_id):
        try:
            agent_group_path = path.join(common.groups_path, agent_id)
            new_file = not path.exists(agent_group_path)

            with open(agent_group_path, 'w') as f_group:
                f_group.write(group_id)

            if new_file:
                chown(agent_group_path, common.wazuh_uid(), common.wazuh_gid())
                chmod(agent_group_path, 0o660)
        except Exception as e:
            raise WazuhInternalError(1005, extra_message=str(e))

    @staticmethod
    def unset_single_group_agent(agent_id, group_id, force=False):
        """Unset the agent group. If agent has multigroups, it will preserve all previous groups except the last one.

        :param agent_id: Agent ID.
        :param group_id: Group ID.
        :param force: Do not check if agent or group exists
        :return: Confirmation message.
        """
        if not force:
            # Check if agent exists, it is not 000 and the group exists
            Agent(agent_id).get_basic_information()

            if agent_id == "000":
                raise WazuhError(1703)

            if not Agent.group_exists(group_id):
                raise WazuhResourceNotFound(1710)

        # Get agent's group
        group_name = Agent.get_agents_group_file(agent_id)
        group_list = group_name.split(',')
        # Check agent belongs to group group_id
        if group_id not in group_list:
            raise WazuhError(1734)
        elif group_id == 'default' and len(group_list) == 1:
            raise WazuhError(1745)
        # Remove group from group_list
        group_list.remove(group_id)
        set_default = False
        if len(group_list) > 1:
            multigroup_name = ','.join(group_list)
        elif not group_list:
            set_default = True
            multigroup_name = 'default'
        else:
            multigroup_name = group_list[0]
        # Update group file
        Agent.set_agent_group_file(agent_id, multigroup_name)

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
    elif field_name in ['dateAdd', 'lastKeepAlive']:
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
    """Expand a certain group or all (*) of them

    :param group_name: Name of the group to be expanded
    :return: List of agents ids
    """
    agents_ids = set()
    if group_name == '*':
        for file in listdir(common.groups_path):
            try:
                if path.getsize(path.join(common.groups_path, file)) > 0:
                    agents_ids.add(file)
            except FileNotFoundError:
                # Agent group removed while running through listed dir
                pass
    else:
        for file in listdir(common.groups_path):
            try:
                with open(path.join(common.groups_path, file), 'r') as f:
                    file_content = f.readlines()
                len(file_content) == 1 and group_name in file_content[0].split(',') and agents_ids.add(file)
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


def agents_padding(result, agent_list):
    """Remove agent 000 from agent_list and transform the format of the agent ids to the general format

    Parameters
    ----------
    result : AffectedItemsWazuhResult
    agent_list : list
        List of agent's IDs

    Returns
    -------
    Formatted agent list
    """
    agent_list = [str(agent).zfill(3) for agent in agent_list]
    if '000' in agent_list:
        result.add_failed_item(id_='000', error=WazuhError(code=1703))
        agent_list.remove('000')

    return agent_list


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
    if not get_result:
        msg = {'version': 1,
               'origin': {'module': 'api'},
               'command': command,
               'parameters': {
                   'agents': agents_chunk,
                   'version': version,
                   'force_upgrade': force,
                   'use_http': use_http,
                   'wpk_repo': wpk_repo,
                   'file_path': file_path,
                   'installer': installer
               }
               }
    else:
        msg = {'version': 1, 'origin': {'module': 'api'}, 'command': command,
               'module': 'api', 'parameters': {'agents': agents_chunk}}

    msg['parameters'] = {k: v for k, v in msg['parameters'].items() if v is not None}

    # Send upgrading command
    s = WazuhSocket(common.UPGRADE_SOCKET)
    s.send(dumps(msg).encode())
    data = loads(s.receive().decode())
    s.close()
    for agent_info in data['data']:
        if agent_info['message'] == 'Success':
            agent_info['create_time'] = datetime.strptime(agent_info['create_time'],
                                                          "%Y/%m/%d %H:%M:%S").strftime("%Y-%m-%dT%H:%M:%SZ")
            agent_info['update_time'] = datetime.strptime(agent_info['update_time'],
                                                          "%Y/%m/%d %H:%M:%S").strftime("%Y-%m-%dT%H:%M:%SZ")

    return data
