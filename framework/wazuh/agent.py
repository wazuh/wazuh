# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import hashlib
import operator
from os import chmod, path, listdir
from shutil import copyfile

from wazuh.core import common, configuration
from wazuh.core.InputValidator import InputValidator
from wazuh.core.agent import WazuhDBQueryAgents, WazuhDBQueryGroupByAgents, \
    WazuhDBQueryMultigroups, Agent, WazuhDBQueryGroup, get_agents_info, get_groups
from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.utils import read_cluster_config
from wazuh.core.exception import WazuhError, WazuhInternalError, WazuhException, WazuhPermissionError, \
    WazuhResourceNotFound
from wazuh.core.results import WazuhResult, AffectedItemsWazuhResult
from wazuh.core.utils import chmod_r, chown_r, get_hash, mkdir_with_mode, md5, process_array
from wazuh.rbac.decorators import expose_resources

cluster_enabled = not read_cluster_config()['disabled']
node_id = get_node().get('node') if cluster_enabled else None

@expose_resources(actions=["agent:read"], resources=["agent:id:{agent_list}"], post_proc_func=None)
def get_distinct_agents(agent_list=None, offset=0, limit=common.database_limit, sort=None, search=None, select=None,
                        fields=None, q=None):
    """ Gets all the different combinations that all system agents have for the selected fields. It also indicates the
    total number of agents that have each combination.

    :param agent_list: List of agents ID's.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
    :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
    :param q: Defines query to filter in DB.
    :param fields: Fields to group by
    :return: WazuhResult
    """

    result = AffectedItemsWazuhResult(all_msg='All selected agents information was returned',
                                      some_msg='Some agents information was not returned',
                                      none_msg='No agent information was returned'
                                      )

    if len(agent_list) != 0:
        db_query = WazuhDBQueryGroupByAgents(filter_fields=fields, offset=offset, limit=limit, sort=sort,
                                             search=search, select=select, query=q, filters={'id': agent_list},
                                             min_select_fields=set(), count=True, get_data=True)

        data = db_query.run()
        result.affected_items.extend(data['items'])
        result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=["agent:read"], resources=["agent:id:{agent_list}"], post_proc_func=None)
def get_agents_summary_status(agent_list=None):
    """Counts the number of agents by status.

    :param agent_list: List of agents ID's.
    :return: WazuhResult.
    """
    result = WazuhResult({'active': 0, 'disconnected': 0, 'never_connected': 0, 'pending': 0, 'total': 0})
    if len(agent_list) != 0:
        db_query = WazuhDBQueryAgents(limit=None, select=['status'], filters={'id': agent_list})
        data = db_query.run()

        for agent in data['items']:
            result[agent['status']] += 1
            result['total'] += 1

    return result


@expose_resources(actions=["agent:read"], resources=["agent:id:{agent_list}"], post_proc_func=None)
def get_agents_summary_os(agent_list=None):
    """Gets a list of available OS.

    :param agent_list: List of agents ID's.
    :return: WazuhResult.
    """
    result = AffectedItemsWazuhResult(none_msg='Could not get the operative system of the agents',
                                      all_msg='Showing the operative system of all specified agents',
                                      some_msg='Could not get the operative system of some agents')
    if len(agent_list) != 0:
        db_query = WazuhDBQueryAgents(select=['os.platform'], filters={'id': agent_list},
                                      default_sort_field='os_platform', min_select_fields=set(),
                                      distinct=True)
        query_data = db_query.run()
        query_data['items'] = [row['os']['platform'] for row in query_data['items']]
        result.affected_items = query_data['items']
        result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=["agent:restart"], resources=["agent:id:{agent_list}"],
                  post_proc_kwargs={'exclude_codes': [1701, 1703]})
def restart_agents(agent_list=None):
    """Restarts a list of agents..

    :param agent_list: List of agents ID's.
    :return: AffectedItemsWazuhResult.
    """
    result = AffectedItemsWazuhResult(all_msg='Restart command was sent to all agents',
                                      some_msg='Restart command was not sent to some agents',
                                      none_msg='Restart command was not sent to any agent'
                                      )

    system_agents = get_agents_info()
    for agent_id in agent_list:
        try:
            if agent_id not in system_agents:
                raise WazuhResourceNotFound(1701)
            if agent_id == "000":
                raise WazuhError(1703)
            Agent(agent_id).restart()
            result.affected_items.append(agent_id)
        except WazuhException as e:
            result.add_failed_item(id_=agent_id, error=e)

    result.total_affected_items = len(result.affected_items)
    result.affected_items.sort(key=int)

    return result


@expose_resources(actions=['cluster:read'], resources=[f'node:id:{node_id}'], post_proc_func=None)
def restart_agents_by_node(agent_list=None):
    """Restart all agents belonging to a node.

    Parameters
    ----------
    agent_list : list, optional
        List of agents. Default `None`
    node_id : str, optional
        Node name. Only used for RBAC. Default `None`

    Returns
    -------
    AffectedItemsWazuhResult
    """
    '000' in agent_list and agent_list.remove('000')

    return restart_agents(agent_list=agent_list)


@expose_resources(actions=["agent:read"], resources=["agent:id:{agent_list}"],
                  post_proc_kwargs={'exclude_codes': [1701]})
def get_agents(agent_list=None, offset=0, limit=common.database_limit, sort=None, search=None, select=None,
               filters=None, q=None):
    """Gets a list of available agents with basic attributes.

    :param agent_list: List of agents ID's.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
    :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
    :param filters: Defines required field filters. Format: {"field1":"value1", "field2":["value2","value3"]}
    :param q: Defines query to filter in DB.
    :return: AffectedItemsWazuhResult.
    """
    result = AffectedItemsWazuhResult(all_msg='All selected agents information was returned',
                                      some_msg='Some agents information was not returned',
                                      none_msg='No agent information was returned'
                                      )
    if len(agent_list) != 0:
        if filters is None:
            filters = dict()
        filters['id'] = agent_list

        system_agents = get_agents_info()
        for agent_id in agent_list:
            if agent_id not in system_agents:
                result.add_failed_item(id_=agent_id, error=WazuhResourceNotFound(1701))

        db_query = WazuhDBQueryAgents(offset=offset, limit=limit, sort=sort, search=search, select=select,
                                      filters=filters, query=q)
        data = db_query.run()
        result.affected_items.extend(data['items'])
        result.total_affected_items = data['totalItems']

    return result


def get_agent_by_name(name=None, select=None):
    """Gets an agent by its name.

    :param name: Agent_name.
    :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
    :return: AffectedItemsWazuhResult.
    """
    db_query = WazuhDBQueryAgents(filters={'name': name})
    data = db_query.run()
    try:
        agent = data['items'][0]['id']
        return get_agents(agent_list=[agent], select=select)
    except IndexError:
        raise WazuhResourceNotFound(1754)
    except Exception as e:
        if e.code == 4000:
            raise WazuhPermissionError(4000)
        raise e


@expose_resources(actions=["group:read"], resources=["group:id:{group_list}"], post_proc_func=None)
def get_agents_in_group(group_list, offset=0, limit=common.database_limit, sort=None, search=None, select=None,
                        filters=None, q=None):
    """Gets a list of available agents with basic attributes.

    :param group_list: Group ID.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
    :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}.
    :param filters: Defines required field filters. Format: {"field1":"value1", "field2":["value2","value3"]}.
    :param q: Defines query to filter in DB.
    :return: AffectedItemsWazuhResult.
    """
    if group_list[0] not in get_groups():
        raise WazuhResourceNotFound(1710)

    q = 'group=' + group_list[0] + (';' + q if q else '')

    return get_agents(offset=offset, limit=limit, sort=sort, search=search, select=select, filters=filters, q=q)


@expose_resources(actions=["agent:read"], resources=["agent:id:{agent_list}"],
                  post_proc_kwargs={'exclude_codes': [1701]})
def get_agents_keys(agent_list=None):
    """Get the key of existing agents.

    :param agent_list: List of agents ID's.
    :return: AffectedItemsWazuhResult.
    """
    result = AffectedItemsWazuhResult(all_msg='Obtained keys for all selected agents',
                                      some_msg='Some agent keys were not obtained',
                                      none_msg='No agent keys were obtained'
                                      )
    system_agents = get_agents_info()
    for agent_id in agent_list:
        try:
            if agent_id not in system_agents:
                raise WazuhResourceNotFound(1701)
            result.affected_items.append({'id': agent_id, 'key': Agent(agent_id).get_key()})
        except WazuhException as e:
            result.add_failed_item(id_=agent_id, error=e)
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=["agent:delete"], resources=["agent:id:{agent_list}"],
                  post_proc_kwargs={'exclude_codes': [1701, 1703]})
def delete_agents(agent_list=None, backup=False, purge=False, status="all", older_than="7d", use_only_authd=False):
    """Deletes a list of agents.

    :param agent_list: List of agents ID's.
    :param backup: Create backup before removing the agent.
    :param purge: Delete definitely from key store.
    :param older_than:  Filters out disconnected agents for longer than specified. Time in seconds | "[n_days]d" |
    "[n_hours]h" | "[n_minutes]m" | "[n_seconds]s". For never_connected agents, uses the register date.
    :param status: Filters by agent status: active, disconnected or never_connected. Multiples statuses separated
    by commas.
    :param use_only_authd: Force the use of authd when adding and removing agents.
    :return: AffectedItemsWazuhResult.
    """
    result = AffectedItemsWazuhResult(all_msg='All selected agents were deleted',
                                      some_msg='Some agents were not deleted',
                                      none_msg='No agents were deleted'
                                      )
    if len(agent_list) != 0:
        db_query = WazuhDBQueryAgents(limit=None, select=["id"], filters={'older_than': older_than, 'status': status,
                                                                          'id': agent_list})
        data = db_query.run()
        can_purge_agents = list(map(operator.itemgetter('id'), data['items']))
        system_agents = get_agents_info()
        for agent_id in agent_list:
            try:
                if agent_id == "000":
                    raise WazuhError(1703)
                elif agent_id not in system_agents:
                    raise WazuhResourceNotFound(1701)
                else:
                    my_agent = Agent(agent_id)
                    my_agent.load_info_from_db()
                    if agent_id not in can_purge_agents:
                        raise WazuhError(
                            1731,
                            extra_message="The agent has a status different to '{0}' or the specified time "
                                          "frame 'older_than {1}' does not apply".format(status, older_than)
                        )
                    my_agent.remove(backup=backup, purge=purge, use_only_authd=use_only_authd)
                    result.affected_items.append(agent_id)
            except WazuhException as e:
                result.add_failed_item(id_=agent_id, error=e)
        result.total_affected_items = len(result.affected_items)
        result.affected_items.sort(key=int)
        result['older_than'] = older_than

    return result


@expose_resources(actions=["agent:create"], resources=["*:*:*"], post_proc_func=None)
def add_agent(name=None, agent_id=None, key=None, ip='any', force_time=-1, use_only_authd=False):
    """Adds a new Wazuh agent.

    :param name: name of the new agent.
    :param agent_id: id of the new agent.
    :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
    :param key: key of the new agent.
    :param force_time: Remove old agent with same IP if disconnected since <force_time> seconds.
    :param use_only_authd: Force the use of authd when adding and removing agents.
    :return: Agent ID and Agent key.
    """
    # Check length of agent name
    if len(name) > 128:
        raise WazuhError(1738)

    new_agent = Agent(name=name, ip=ip, id=agent_id, key=key, force=force_time, use_only_authd=use_only_authd)

    return WazuhResult({'id': new_agent.id, 'key': new_agent.key})


@expose_resources(actions=["group:read"], resources=["group:id:{group_list}"],
                  post_proc_kwargs={'exclude_codes': [1710]})
def get_agent_groups(group_list=None, offset=0, limit=None, sort=None, search=None, hash_algorithm='md5'):
    """Gets the existing groups.

    :param group_list: List of Group names.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Fields to sort the items by.
    :param search: Text to search.
    :param hash_algorithm: hash algorithm used to get mergedsum and configsum.
    :return: AffectedItemsWazuhResult.
    """

    affected_groups = list()
    result = AffectedItemsWazuhResult(all_msg='All selected groups information was returned',
                                      some_msg='Some groups information was not returned',
                                      none_msg='No group information was returned'
                                      )

    # Add failed items
    for invalid_group in set(group_list) - get_groups():
        result.add_failed_item(id_=invalid_group, error=WazuhResourceNotFound(1710))

    group_query = WazuhDBQueryGroup(filters={'name': group_list}, offset=offset, limit=limit, sort=sort, search=search)
    query_data = group_query.run()

    for group in query_data['items']:
        full_entry = path.join(common.shared_path, group['name'])

        # merged.mg and agent.conf sum
        merged_sum = get_hash(path.join(full_entry, "merged.mg"), hash_algorithm)
        conf_sum = get_hash(path.join(full_entry, "agent.conf"), hash_algorithm)

        if merged_sum:
            group['mergedSum'] = merged_sum

        if conf_sum:
            group['configSum'] = conf_sum
        affected_groups.append(group)

    result.affected_items = affected_groups
    result.total_affected_items = query_data['totalItems']

    return result


@expose_resources(actions=["group:read"], resources=["group:id:{group_list}"], post_proc_func=None)
def get_group_files(group_list=None, offset=0, limit=None, search_text=None, search_in_fields=None,
                    complementary_search=False, sort_by=None, sort_ascending=True, hash_algorithm='md5'):
    """Gets the group files.

    :param group_list: List of Group names.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by.
    :param sort_ascending: Sort in ascending (true) or descending (false) order.
    :param search_text: Text to search.
    :param complementary_search: Find items without the text to search.
    :param search_in_fields: Fields to search in.
    :param hash_algorithm: hash algorithm used to get mergedsum and configsum.
    :return: WazuhResult.
    """
    # We access unique group_id from list, this may change if and when we decide to add option to get files for
    # a list of groups
    group_id = group_list[0]
    group_path = common.shared_path
    result = AffectedItemsWazuhResult(all_msg='All selected groups files were returned',
                                      some_msg='Some groups files were not returned',
                                      none_msg='No groups files were returned'
                                      )
    if group_id:
        if not Agent.group_exists(group_id):
            result.add_failed_item(id_=group_id, error=WazuhResourceNotFound(1710))
            return result
        group_path = path.join(common.shared_path, group_id)

    if not path.exists(group_path):
        result.add_failed_item(id_=group_path, error=WazuhError(1006))
        return result

    try:
        data = []
        for entry in listdir(group_path):
            item = dict()
            item['filename'] = entry
            item['hash'] = get_hash(path.join(group_path, entry), hash_algorithm)
            data.append(item)

        # ar.conf
        ar_path = path.join(common.shared_path, 'ar.conf')
        data.append({'filename': "ar.conf", 'hash': get_hash(ar_path, hash_algorithm)})
        data = process_array(data, search_text=search_text, search_in_fields=search_in_fields,
                             complementary_search=complementary_search, sort_by=sort_by,
                             sort_ascending=sort_ascending, offset=offset, limit=limit)
        result.affected_items = data['items']
        result.total_affected_items = data['totalItems']
    except WazuhError as e:
        result.add_failed_item(id_=group_path, error=e)
        raise e
    except Exception as e:
        raise WazuhInternalError(1727, extra_message=str(e))

    return result


@expose_resources(actions=["group:create"], resources=["*:*:*"], post_proc_func=None)
def create_group(group_id):
    """Creates a group.

    :param group_id: Group ID.
    :return: Confirmation message.
    """
    # Input Validation of group_id
    if not InputValidator().group(group_id):
        raise WazuhError(1722)

    group_path = path.join(common.shared_path, group_id)

    if group_id.lower() == "default" or path.exists(group_path):
        raise WazuhError(1711, extra_message=group_id)

    # Create group in /etc/shared
    group_def_path = path.join(common.shared_path, 'agent-template.conf')
    try:
        mkdir_with_mode(group_path)
        copyfile(group_def_path, path.join(group_path, 'agent.conf'))
        chown_r(group_path, common.ossec_uid(), common.ossec_gid())
        chmod_r(group_path, 0o660)
        chmod(group_path, 0o770)
        msg = f"Group '{group_id}' created."
    except Exception as e:
        raise WazuhInternalError(1005, extra_message=str(e))

    return WazuhResult({'message': msg})


@expose_resources(actions=["group:delete"], resources=["group:id:{group_list}"],
                  post_proc_kwargs={'exclude_codes': [1710, 1712]})
def delete_groups(group_list=None):
    """Delete a list of groups and remove it from every agent assignments.

    :param group_list: List of Group names.
    :return: AffectedItemsWazuhResult.
    """
    result = AffectedItemsWazuhResult(all_msg='All selected groups were deleted',
                                      some_msg='Some groups were not deleted',
                                      none_msg='No group was deleted')

    affected_agents = set()
    system_groups = get_groups()
    for group_id in group_list:
        try:
            # Check if group exists
            if group_id not in system_groups:
                raise WazuhResourceNotFound(1710)
            if group_id == 'default':
                raise WazuhError(1712)
            agent_list = list(map(operator.itemgetter('id'),
                                  WazuhDBQueryMultigroups(group_id=group_id, limit=None).run()['items']))
            try:
                affected_agents_result = remove_agents_from_group(agent_list=agent_list, group_list=[group_id])
                if affected_agents_result.total_failed_items != 0:
                    raise WazuhError(4015)
            except WazuhError:
                raise WazuhError(4015)
            Agent.delete_single_group(group_id)
            result.affected_items.append(group_id)
            affected_agents.update(affected_agents_result.affected_items)
        except WazuhException as e:
            result.add_failed_item(id_=group_id, error=e)

    result['affected_agents'] = sorted(affected_agents, key=int)
    result.affected_items.sort()
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=["group:modify_assignments"], resources=['group:id:{replace_list}'], post_proc_func=None)
@expose_resources(actions=["group:modify_assignments"], resources=['group:id:{group_list}'], post_proc_func=None)
@expose_resources(actions=["agent:modify_group"], resources=["agent:id:{agent_list}"],
                  post_proc_kwargs={'exclude_codes': [1701, 1703, 1751, 1752, 1753]})
def assign_agents_to_group(group_list=None, agent_list=None, replace=False, replace_list=None):
    """Assign a list of agents to a group.

    :param group_list: List of Group names.
    :param agent_list: List of Agent IDs.
    :param replace: Whether to append new group to current agent's group or replace it.
    :param replace_list: List of Group names that can be replaced.
    :return: AffectedItemsWazuhResult.
    """
    group_id = group_list[0]
    result = AffectedItemsWazuhResult(all_msg=f'All selected agents were assigned to {group_id}'
                                              f'{" and removed from the other groups" if replace else ""}',
                                      some_msg=f'Some agents were not assigned to {group_id}'
                                               f'{" and removed from the other groups" if replace else ""}',
                                      none_msg='No agents were assigned to {0}'.format(group_id)
                                      )
    # Check if the group exists
    if not Agent.group_exists(group_id):
        raise WazuhResourceNotFound(1710)
    system_agents = get_agents_info()
    for agent_id in agent_list:
        try:
            if agent_id not in system_agents:
                raise WazuhResourceNotFound(1701)
            if agent_id == "000":
                raise WazuhError(1703)
            Agent.add_group_to_agent(group_id, agent_id, force=True, replace=replace, replace_list=replace_list)
            result.affected_items.append(agent_id)
        except WazuhException as e:
            result.add_failed_item(id_=agent_id, error=e)

    result.total_affected_items = len(result.affected_items)
    result.affected_items.sort(key=int)

    return result


@expose_resources(actions=["group:modify_assignments"], resources=['group:id:{group_list}'], post_proc_func=None)
@expose_resources(actions=["agent:modify_group"], resources=['agent:id:{agent_list}'], post_proc_func=None)
def remove_agent_from_group(group_list=None, agent_list=None):
    """Removes an agent assignment from a specified group.

    :param group_list: List of Group names.
    :param agent_list: List of Agent IDs.
    :return: Confirmation message.
    """
    group_id = group_list[0]
    agent_id = agent_list[0]

    # Check if agent and group exist and it is not 000
    if agent_id not in get_agents_info():
        raise WazuhResourceNotFound(1701)
    if agent_id == '000':
        raise WazuhError(1703)
    if group_id not in get_groups():
        raise WazuhResourceNotFound(1710)

    return WazuhResult({'message': Agent.unset_single_group_agent(agent_id=agent_id, group_id=group_id, force=True)})


@expose_resources(actions=["agent:modify_group"], resources=["agent:id:{agent_list}"], post_proc_func=None)
@expose_resources(actions=["group:modify_assignments"], resources=["group:id:{group_list}"],
                  post_proc_kwargs={'exclude_codes': [1710, 1734, 1745]})
def remove_agent_from_groups(agent_list=None, group_list=None):
    """Removes an agent assigment from a list of groups.

    :param agent_list: List of agents ID's.
    :param group_list: List of Group names.
    :return: AffectedItemsWazuhResult.
    """
    agent_id = agent_list[0]
    result = AffectedItemsWazuhResult(all_msg='Specified agent was removed from returned groups',
                                      some_msg='Specified agent was not removed from some groups',
                                      none_msg='Specified agent was not removed from any group'
                                      )

    # Check if agent exists and it is not 000
    if agent_id == '000':
        raise WazuhError(1703)
    if agent_id not in get_agents_info():
        raise WazuhResourceNotFound(1701)

    # We move default group to last position in case it is contained in group_list. When an agent is removed from all
    # groups it is reverted to 'default'. We try default last to avoid removing it and then adding again.
    try:
        group_list.append(group_list.pop(group_list.index('default')))
    except ValueError:
        pass

    system_groups = get_groups()
    for group_id in group_list:
        try:
            if group_id not in system_groups:
                raise WazuhResourceNotFound(1710)
            Agent.unset_single_group_agent(agent_id=agent_id, group_id=group_id, force=True)
            result.affected_items.append(group_id)
        except WazuhException as e:
            result.add_failed_item(id_=group_id, error=e)
    result.total_affected_items = len(result.affected_items)
    result.affected_items.sort()

    return result


@expose_resources(actions=["group:modify_assignments"], resources=["group:id:{group_list}"], post_proc_func=None)
@expose_resources(actions=["agent:modify_group"], resources=["agent:id:{agent_list}"],
                  post_proc_kwargs={'exclude_codes': [1701, 1703, 1734]})
def remove_agents_from_group(agent_list=None, group_list=None):
    """Remove a list of agents assignment from a specified group.

    :param agent_list: List of agents ID's.
    :param group_list: List of Group names.
    :return: AffectedItemsWazuhResult.
    """
    group_id = group_list[0]
    result = AffectedItemsWazuhResult(all_msg=f'All selected agents were removed from group {group_id}',
                                      some_msg=f'Some agents were not removed from group {group_id}',
                                      none_msg=f'No agent was removed from group {group_id}'
                                      )
    # Check if group exists
    if group_id not in get_groups():
        raise WazuhResourceNotFound(1710)

    for agent_id in agent_list:
        try:
            if agent_id == '000':
                raise WazuhError(1703)
            if agent_id not in get_agents_info():
                raise WazuhResourceNotFound(1701)
            Agent.unset_single_group_agent(agent_id=agent_id, group_id=group_id, force=True)
            result.affected_items.append(agent_id)
        except WazuhException as e:
            result.add_failed_item(id_=agent_id, error=e)
    result.total_affected_items = len(result.affected_items)
    result.affected_items.sort(key=int)

    return result


@expose_resources(actions=["agent:read"], resources=["agent:id:{agent_list}"], post_proc_func=None)
def get_outdated_agents(agent_list=None, offset=0, limit=common.database_limit, sort=None, search=None, select=None,
                        q=None):
    """Gets the outdated agents.

    :param agent_list: List of agents ID's.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string.
    :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
    :param q: Defines query to filter in DB.
    :return: AffectedItemsWazuhResult.
    """

    result = AffectedItemsWazuhResult(all_msg='All selected agents information was returned',
                                      some_msg='Some agents information was not returned',
                                      none_msg='No agent information was returned'
                                      )
    if len(agent_list) != 0:
        # Get manager version
        manager = Agent(id='000')
        manager.load_info_from_db()

        select = ['version', 'id', 'name'] if select is None else select
        db_query = WazuhDBQueryAgents(offset=offset, limit=limit, sort=sort, search=search, select=select,
                                      query=f"version!={manager.version}" + (';' + q if q else ''),
                                      filters={'id': agent_list})
        data = db_query.run()
        result.affected_items = data['items']
        result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=["agent:upgrade"], resources=["agent:id:{agent_list}"], post_proc_func=None)
def upgrade_agents(agent_list=None, wpk_repo=None, version=None, force=False, chunk_size=None, use_http=False):
    """Read upgrade result output from agent.

    :param agent_list: List of agents ID's.
    :param wpk_repo: URL for WPK download.
    :param version: Version to upgrade to.
    :param force: force the update even if it is a downgrade.
    :param chunk_size: size of each update chunk.
    :param use_http: False for HTTPS protocol, True for HTTP protocol.
    :return: Upgrade message.
    """
    # We access unique agent_id from list, this may change if and when we decide to add option to upgrade a list of
    # agents
    agent_id = agent_list[0]

    return Agent(agent_id).upgrade(wpk_repo=wpk_repo, version=version, force=True if int(force) == 1 else False,
                                   chunk_size=chunk_size, use_http=use_http)


@expose_resources(actions=["agent:upgrade"], resources=["agent:id:{agent_list}"], post_proc_func=None)
def get_upgrade_result(agent_list=None, timeout=3):
    """Read upgrade result output from agent.

    :param agent_list: List of agents ID's.
    :param timeout: Maximum time for the call to be considered failed.
    :return: Upgrade result.
    """
    # We access unique agent_id from list, this may change if and when we decide to add option to upgrade a list of
    # agents
    agent_id = agent_list[0]

    return Agent(agent_id).upgrade_result(timeout=int(timeout))


@expose_resources(actions=["agent:upgrade"], resources=["agent:id:{agent_list}"], post_proc_func=None)
def upgrade_agents_custom(agent_list=None, file_path=None, installer=None):
    """Read upgrade result output from agent.

    :param agent_list: List of agents ID's.
    :param file_path: Path to the installation file.
    :param installer: Selected installer.
    :return: Upgrade message.
    """
    # We access unique agent_id from list, this may change if and when we decide to add option to upgrade a list of
    # agents
    agent_id = agent_list[0]

    return Agent(agent_id).upgrade_custom(file_path=file_path, installer=installer)


@expose_resources(actions=["agent:read"], resources=["agent:id:{agent_list}"], post_proc_func=None)
def get_agent_config(agent_list=None, component=None, config=None):
    """Read selected configuration from agent.

    :param agent_list: List of agents ID's.
    :param component: Selected component.
    :param config: Configuration to get, written on disk.
    :return: WazuhResult(Loaded configuration in JSON).
    """
    # We access unique agent_id from list, this may change if and when we decide a final way to handle get responses
    # with failed ids and a list of agents
    agent_id = agent_list[0]
    my_agent = Agent(agent_id)
    my_agent.load_info_from_db()

    if my_agent.status != "active":
        raise WazuhError(1740)

    return WazuhResult(my_agent.getconfig(component=component, config=config))


@expose_resources(actions=["agent:read"], resources=["agent:id:{agent_list}"],
                  post_proc_kwargs={'exclude_codes': [1701, 1703]})
def get_agents_sync_group(agent_list=None):
    """Get agents configuration sync status.

    :param agent_list: List of agents ID's.
    :return AffectedItemsWazuhResult.
    """
    result = AffectedItemsWazuhResult(all_msg='Sync info was returned for all selected agents',
                                      some_msg='Sync info was not returned for some selected agents',
                                      none_msg='No sync info was returned',
                                      )

    system_agents = get_agents_info()
    for agent_id in agent_list:
        try:
            if agent_id == "000":
                raise WazuhError(1703)
            if agent_id not in system_agents:
                raise WazuhResourceNotFound(1701)
            else:
                # Check if agent exists and it is active
                agent_info = Agent(agent_id).get_basic_information()
                # Check if it has a multigroup
                if len(agent_info['group']) > 1:
                    multi_group = ','.join(agent_info['group'])
                    multi_group = hashlib.sha256(multi_group.encode()).hexdigest()[:8]
                    group_merged_path = path.join(common.multi_groups_path, multi_group, "merged.mg")
                else:
                    group_merged_path = path.join(common.shared_path, agent_info['group'][0], "merged.mg")
                result.affected_items.append({'id': agent_id,
                                              'synced': md5(group_merged_path) == agent_info['mergedSum']})
        except (IOError, KeyError):
            # The file couldn't be opened and therefore the group has not been synced
            result.affected_items.append({'id': agent_id, 'synced': False})
        except WazuhException as e:
            result.add_failed_item(id_=agent_id, error=e)

    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=["group:read"], resources=["group:id:{group_list}"], post_proc_func=None)
def get_file_conf(group_list=None, type_conf=None, return_format=None, filename=None):
    """ Reads configuration file for specified group.

    :param group_list: List of Group names.
    :param type_conf: Type of file.
    :param return_format: Format of the answer (xml or json).
    :param filename: Filename to read config from.
    :return: WazuhResult.
    """
    # We access unique group_id from list, this may change if and when we decide to add option to get configuration
    # files for a list of groups
    group_id = group_list[0]

    return WazuhResult({'data': configuration.get_file_conf(filename, group_id=group_id, type_conf=type_conf,
                                                            return_format=return_format)})


@expose_resources(actions=["group:read"], resources=["group:id:{group_list}"], post_proc_func=None)
def get_agent_conf(group_list=None, filename='agent.conf', offset=0, limit=common.database_limit):
    """ Reads agent conf for specified group.

    :param group_list: List of Group names.
    :param filename: Filename to read config from.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :return: WazuhResult.
    """
    # We access unique group_id from list, this may change if and when we decide to add option to get agent conf for
    # a list of groups
    group_id = group_list[0]

    return WazuhResult(configuration.get_agent_conf(group_id=group_id, filename=filename, offset=offset, limit=limit))


@expose_resources(actions=["group:update_config"], resources=["group:id:{group_list}"], post_proc_func=None)
def upload_group_file(group_list=None, file_data=None, file_name='agent.conf'):
    """Updates a group file.

    :param group_list: List of Group names.
    :param file_data: Relative path of temporary file to upload.
    :param file_name: File name to update.
    :return: Confirmation message.
    """
    # We access unique group_id from list, this may change if and when we decide to add option to update files for
    # a list of groups
    group_id = group_list[0]

    return WazuhResult({'message': configuration.upload_group_file(group_id, file_data, file_name=file_name)})


def get_full_overview() -> WazuhResult:
    """Get information about agents.

    :return: Dictionary with information about agents
    """
    # get information from different methods of Agent class
    stats_distinct_node = get_distinct_agents(fields=['node_name']).affected_items
    groups = get_agent_groups().affected_items
    stats_distinct_os = get_distinct_agents(fields=['os.name',
                                                    'os.platform', 'os.version']).affected_items
    stats_version = get_distinct_agents(fields=['version']).affected_items
    summary = get_agents_summary_status()
    try:
        last_registered_agent = [get_agents(limit=1,
                                            sort={'fields': ['dateAdd'], 'order': 'desc'},
                                            q='id!=000').affected_items[0]]
    except IndexError:  # an IndexError could happen if there are not registered agents
        last_registered_agent = []
    # combine results in an unique dictionary
    result = {'nodes': stats_distinct_node, 'groups': groups, 'agent_os': stats_distinct_os, 'agent_status': summary,
              'agent_version': stats_version, 'last_registered_agent': last_registered_agent}

    return WazuhResult(result)
