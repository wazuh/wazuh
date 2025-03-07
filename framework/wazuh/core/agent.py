# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

import ipaddress
import re
from base64 import b64encode
from functools import lru_cache
from os import listdir, path, remove
from pathlib import Path
from typing import List, Optional

from wazuh.core import common, configuration
from wazuh.core.cluster.utils import get_manager_status
from wazuh.core.exception import WazuhError, WazuhException, WazuhInternalError, WazuhResourceNotFound
from wazuh.core.indexer import get_indexer_client
from wazuh.core.indexer.base import IndexerKey
from wazuh.core.indexer.models.agent import Agent as IndexerAgent
from wazuh.core.InputValidator import InputValidator
from wazuh.core.utils import (
    GROUP_FILE_EXT,
    WazuhVersion,
    get_date_from_timestamp,
    get_group_file_path,
)
from wazuh.core.wazuh_queue import WazuhQueue
from wazuh.core.wazuh_socket import WazuhSocketJSON
from wazuh.core.wdb import WazuhDBConnection


class Agent:
    """Wazuh Agent object."""

    # TODO(#25121): Remove old fields.
    fields = {
        'id': 'id',
        'name': 'name',
        'ip': 'coalesce(ip,register_ip)',
        'status': 'connection_status',
        'os.name': 'os_name',
        'os.version': 'os_version',
        'os.platform': 'os_platform',
        'version': 'version',
        'manager': 'manager_host',
        'dateAdd': 'date_add',
        'group': '`group`',
        'mergedSum': 'merged_sum',
        'configSum': 'config_sum',
        'os.codename': 'os_codename',
        'os.major': 'os_major',
        'os.minor': 'os_minor',
        'os.uname': 'os_uname',
        'os.arch': 'os_arch',
        'os.build': 'os_build',
        'node_name': 'node_name',
        'lastKeepAlive': 'last_keepalive',
        'internal_key': 'internal_key',
        'registerIP': 'register_ip',
        'disconnection_time': 'disconnection_time',
        'group_config_status': 'group_config_status',
        'status_code': 'status_code',
    }

    new_fields = {
        'id': 'id',
        'name': 'name',
        'key': 'key',
        'groups': 'groups',
        'type': 'type',
        'version': 'version',
        'last_login': 'last_login',
        'persistent_connection_mode': 'persistent_connection_mode',
    }

    def __init__(self, id: str = None, name: str = None, ip: str = None, key: str = None, force: dict = None):
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
        self.group_config_status = None
        self.status_code = None

        # If the method has only been called with an ID parameter, no new agent should be added.
        # Otherwise, a new agent must be added
        if name is not None and ip is not None:
            self._add(name=name, ip=ip, id=id, key=key, force=force)

    def __str__(self) -> str:
        return str(self.to_dict())

    def to_dict(self) -> dict:
        dictionary = {
            'id': self.id,
            'name': self.name,
            'ip': self.ip,
            'internal_key': self.internal_key,
            'os': self.os,
            'version': self.version,
            'dateAdd': self.dateAdd,
            'lastKeepAlive': self.lastKeepAlive,
            'status': self.status,
            'key': self.key,
            'configSum': self.configSum,
            'mergedSum': self.mergedSum,
            'group': self.group,
            'manager': self.manager,
            'node_name': self.node_name,
            'disconnection_time': self.disconnection_time,
            'group_config_status': self.group_config_status,
            'status_code': self.status_code,
        }

        return dictionary

    def load_info_from_db(self, select: list = None):
        """Gets attributes of existing agent.

        Parameters
        ----------
        select : list
            Select fields to return. Format: ["field1","field2"].

        Raises
        ------
        WazuhResourceNotFound(1701)
            Agent does not exist.
        """
        with WazuhDBQueryAgents(
            offset=0,
            limit=None,
            sort=None,
            search=None,
            select=select,
            query='id={}'.format(self.id),
            count=False,
            get_data=True,
            remove_extra_fields=False,
        ) as db_query:
            try:
                data = db_query.run()['items'][0]
            except IndexError:
                raise WazuhResourceNotFound(1701)

        list(map(lambda x: setattr(self, x[0], x[1]), data.items()))

    def get_basic_information(self, select: list = None):
        """Gets public attributes of existing agent.

        Parameters
        ----------
        select : list
            Select fields to return. Format: ["field1","field2"].
        """
        self.load_info_from_db(select)
        fields = (
            set(self.fields.keys()) & set(select) if select is not None else set(self.fields.keys()) - {'internal_key'}
        )
        return {field: getattr(self, field) for field in map(lambda x: x.split('.')[0], fields) if getattr(self, field)}

    def compute_key(self) -> str:
        """Compute agent key.

        Returns
        -------
        str
            Agent key.
        """
        str_key = '{0} {1} {2} {3}'.format(self.id, self.name, self.registerIP, self.internal_key)
        return b64encode(str_key.encode()).decode()

    def get_key(self) -> str:
        """Get agent key.

        Returns
        -------
        str
            Agent key.
        """
        self.load_info_from_db()
        self.key = self.compute_key()

        return self.key

    def reconnect(self, wq: WazuhQueue) -> str:
        """Force reconnect to the manager.

        Parameters
        ----------
        wq : WazuhQueue
            WazuhQueue used for the active response message.

        Raises
        ------
        WazuhError(1707)
            If the agent to be reconnected is not active.

        Returns
        -------
        str
            Message generated by Wazuh.
        """
        # TODO(#25121): the behavior should be reviewed in the corresponding use case.
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
        str
            Message generated by Wazuh.
        """
        # Check that wazuh-authd is running
        try:
            manager_status = get_manager_status(cache=True)
        except WazuhInternalError as e:
            # wazuh-authd is not running due to a problem with /proc availability
            raise WazuhError(1726, extra_message=str(e))

        if manager_status.get('wazuh-authd') != 'running':
            # wazuh-authd is not running
            raise WazuhError(1726)

        # Delete agent
        try:
            data = self._remove_authd(purge)

            return data
        except WazuhException as e:
            raise e
        except Exception as e:
            raise WazuhInternalError(1757, extra_message=str(e))

    def _remove_authd(self, purge: bool = False) -> dict:
        """Delete the agent.

        Parameters
        ----------
        purge : bool
            Delete definitely from key store.

        Returns
        -------
        dict
            Message.
        """
        msg = {'function': 'remove', 'arguments': {'id': str(self.id).zfill(3), 'purge': purge}}

        authd_socket = WazuhSocketJSON(common.AUTHD_SOCKET)
        authd_socket.send(msg)
        data = authd_socket.receive()
        authd_socket.close()

        return data

    def _add(self, name: str, ip: str, id: str = None, key: str = None, force: bool = None):
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
        # Check IP is available and valid
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

        # Check that wazuh-authd is running
        try:
            manager_status = get_manager_status()
        except WazuhInternalError as e:
            # wazuh-authd is not running due to a problem with /proc availability
            raise WazuhError(1726, extra_message=str(e))

        if manager_status.get('wazuh-authd') != 'running':
            # wazuh-authd is not running
            raise WazuhError(1726)

        # Add agent
        try:
            self._add_authd(name, ip, id, key, force)
        except WazuhException as e:
            raise e
        except Exception as e:
            raise WazuhInternalError(1725, extra_message=str(e))

    def _add_authd(self, name: str, ip: str, id: str = None, key: str = None, force: bool = None):
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

        msg = ''
        if name and ip:
            msg = {'function': 'add', 'arguments': {'name': name, 'ip': ip}}

            if force is not None:
                # This force field must always be present
                force.update({'key_mismatch': True})
                msg['arguments']['force'] = force

            if id:
                msg['arguments'].update({'id': id})

            if key:
                msg['arguments'].update({'key': key})

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
    async def delete_single_group(group_name: str) -> dict:
        """Delete a group.

        Parameters
        ----------
        group_name : str
            Group name.

        Returns
        -------
        dict
            Confirmation message.
        """
        # Delete group file
        group_path = get_group_file_path(group_name)
        if path.exists(group_path):
            try:
                remove(group_path)
            except Exception as e:
                raise WazuhError(1006, extra_message=str(e))

        msg = "Group '{0}' deleted.".format(group_name)
        return {'message': msg}

    def get_agent_os_name(self) -> str:
        """Return a string with the agent's os name."""
        query = WazuhDBQueryAgents(select=['os.name'], filters={'id': [self.id]})

        try:
            return query.run()['items'][0]['os'].get('name', 'null')
        except KeyError:
            return 'null'

    @staticmethod
    def get_agents_overview(
        offset: int = 0,
        limit: int = common.DATABASE_LIMIT,
        sort: dict = None,
        search: str = None,
        select: set = None,
        filters: dict = None,
        q: str = '',
        count: bool = True,
        get_data: bool = True,
    ) -> dict:
        """Gets a list of available agents with basic attributes.

        Parameters
        ----------
        offset : int
            First item to return.
        limit : int
            Maximum number of items to return.
        sort : dict
            Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        search : str
            Looks for items with the specified string. Format: {"fields": ["field1","field2"]}.
        select : set
            Select fields to return. Format: {"fields":["field1","field2"]}.
        filters : dict
            Defines required field filters.
        q : str
            Defines query to filter in DB.
        count : bool
            Whether to compute totalItems.
        get_data : bool
            Whether to return data.

        Returns
        -------
        dict
            Information gathered from the database query.
        """
        pfilters = (
            get_rbac_filters(system_resources=get_agents_info(), permitted_resources=filters.pop('id'), filters=filters)
            if filters and 'id' in filters
            else {'filters': filters}
        )
        db_query = WazuhDBQueryAgents(
            offset=offset,
            limit=limit,
            sort=sort,
            search=search,
            select=select,
            query=q,
            count=count,
            get_data=get_data,
            **pfilters,
        )
        data = db_query.run()

        return data

    @staticmethod
    async def get(agent_id: str) -> IndexerAgent:
        """Get agent.

        Parameters
        ----------
        agent_id : str
            Agent ID.

        Returns
        -------
        IndexerAgent
            Agent information.
        """
        async with get_indexer_client() as indexer_client:
            return await indexer_client.agents.get(agent_id)

    @staticmethod
    def group_exists(group_id: str) -> bool:
        """Check if the group exists.

        Parameters
        ----------
        group_id : str
            Group ID.

        Raises
        ------
        WazuhError(1722)
            Incorrect format for group_id.

        Returns
        -------
        bool
            True if group exists, False otherwise.
        """
        # Input Validation of group_id
        if not InputValidator().group(group_id):
            raise WazuhError(1722)

        return path.exists(get_group_file_path(group_id))

    @staticmethod
    async def get_agent_groups(agent_id: str) -> Optional[List[str]]:
        """Return all agent's groups.

        Parameters
        ----------
        agent_id : str
            Agent ID.

        Returns
        -------
        Optional[List[str]]
            List of group names or None.
        """
        agent = await Agent.get(agent_id)
        return agent.groups

    @staticmethod
    async def set_agent_group_relationship(agent_id: str, group_id: str, remove: bool = False, override: bool = False):
        """Set a relationship between an agent and a group.

        Parameters
        ----------
        agent_id : str
            ID of the agent.
        group_id : str
            ID of the group.
        remove : bool
            Set the relationship with the remove mode.
        override : bool
            Replace all groups with the specified one. Only works if `remove` is False.
        """
        async with get_indexer_client() as indexer_client:
            if remove:
                await indexer_client.agents.remove_agents_from_group(group_name=group_id, agent_ids=[agent_id])
                return

            await indexer_client.agents.add_agents_to_group(
                group_name=group_id, agent_ids=[agent_id], override=override
            )

    def get_config(self, component: str = '', config: str = '', agent_version: str = '') -> dict:
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
            raise WazuhInternalError(1735, extra_message=f'Minimum required version is {common.ACTIVE_CONFIG_VERSION}')

        return configuration.get_active_configuration(agent_id=self.id, component=component, configuration=config)


def unify_wazuh_upgrade_version_format(upgrade_version: str) -> str:
    """Format the specified upgrade version into the 'vX.Y.Z' standard.

    Parameters
    ----------
    upgrade_version : str
        String with the specified upgrade version.

    Returns
    -------
    str
        Formatted upgrade version.
    """
    if upgrade_version:
        upgrade_version = re.findall(r'\d+\.\d+\.\d+$', upgrade_version, re.IGNORECASE)[0]
        return f'v{upgrade_version}'


def unify_wazuh_version_format(filters: dict):
    """Verify and format the specified wazuh version into the 'wazuh vX.Y.Z' standard.

    Parameters
    ----------
    filters : dict
        Dictionary field filters required by the user.
    """
    wv = filters.get('version')
    if wv is not None:
        if re.match(r'^v?\d+\.\d+\.\d+$', wv, re.IGNORECASE):
            filters['version'] = f'wazuh {"v" if "v" not in wv else ""}{wv}'
        elif re.match(r'^wazuh \d+\.\d+\.\d+$', wv, re.IGNORECASE):
            filters['version'] = f'{wv.replace(" ", " v")}'


def format_fields(field_name: str, value: str) -> str:
    """Give format to values of specific fields.

    Parameters
    ----------
    field_name : str
        Name of the field to be formatted.
    value : str
        Value of the field.
    """
    if field_name == 'id':
        return str(value).zfill(3)
    elif field_name == 'group':
        return value.split(',')
    elif field_name in ['dateAdd', 'lastKeepAlive', 'disconnection_time']:
        return get_date_from_timestamp(value) if not isinstance(value, str) else value
    else:
        return value


@common.async_context_cached('system_agents')
async def get_agents_info() -> set:
    """Get all agent IDs in the system.

    Returns
    -------
    set
        IDs of all agents in the system.
    """
    async with get_indexer_client() as indexer_client:
        query = {IndexerKey.MATCH_ALL: {}}
        agents = await indexer_client.agents.search(query={IndexerKey.QUERY: query}, select='agent.id')
        return set([agent.id for agent in agents])


@common.context_cached('system_groups')
def get_groups() -> set:
    """Get all groups in the system.

    Returns
    -------
    set
        Names of all groups in the system.
    """
    groups = set()
    for group_file in listdir(common.WAZUH_GROUPS):
        filepath = Path(group_file)
        if filepath.suffix == GROUP_FILE_EXT:
            groups.add(filepath.stem)

    return groups


@common.async_context_cached('system_expanded_groups')
async def expand_group(group_name: str) -> set:
    """Expand a certain group or all (*) of them.

    Parameters
    ----------
    group_name : str
        Name of the group to be expanded.

    Returns
    -------
    set
        Set of agent IDs.
    """
    if group_name == '*':
        return await get_agents_info()

    async with get_indexer_client() as indexer_client:
        agents = await indexer_client.agents.get_group_agents(group_name=group_name)
        return set([agent.id for agent in agents])


@lru_cache()
def get_manager_name() -> str:
    """This function read the manager name from global.db.

    Returns
    -------
    str
        Manager name.
    """
    # TODO(#25121): This function needs to be redifined according to the required used case.
    wdb_conn = WazuhDBConnection()
    manager_name = wdb_conn.execute('global sql SELECT name FROM agent WHERE (id = 0)')[0]['name']
    wdb_conn.close()

    return manager_name


def get_rbac_filters(system_resources: set = None, permitted_resources: list = None, filters: dict = None) -> dict:
    """This function calculate the list of allowed or denied depending on the list size.

    Parameters
    ----------
    system_resources : set
        System resources for the current request.
    permitted_resources : list
        Resources granted by RBAC.
    filters : dict
        Dictionary with additional filters for the current request.

    Returns
    -------
    dict
        Dictionary with the original filters plus those added by RBAC.
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
