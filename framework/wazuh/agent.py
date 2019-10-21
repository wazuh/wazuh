# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import hashlib
import operator
from glob import glob
from os import chmod, path, listdir
from shutil import copyfile

from wazuh import common, configuration
from wazuh.InputValidator import InputValidator
from wazuh.core.core_agent import WazuhDBQueryAgents, WazuhDBQueryDistinctAgents, WazuhDBQueryGroupByAgents, \
    WazuhDBQueryMultigroups, Agent
from wazuh.database import Connection
from wazuh.exception import WazuhError, WazuhInternalError, WazuhException
from wazuh.rbac.decorators import expose_resources
from wazuh.results import WazuhResult, AffectedItemsWazuhResult
from wazuh.utils import chmod_r, chown_r, get_hash, mkdir_with_mode, md5, process_array


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
    db_query = WazuhDBQueryGroupByAgents(filter_fields=fields, offset=offset, limit=limit, sort=sort, search=search, 
                                         select=select, query=q, filters={'id': agent_list}, min_select_fields=set(), 
                                         count=True, get_data=True)

    return WazuhResult(db_query.run())


@expose_resources(actions=["agent:read"], resources=["agent:id:{agent_list}"], post_proc_func=None)
def get_agents_summary_status(agent_list=None):
    """Counts the number of agents by status.

    :param agent_list: List of agents ID's.
    :return: WazuhResult
    """
    db_query = WazuhDBQueryAgents(limit=None, select=['status'], filters={'id': agent_list})
    data = db_query.run()

    result = {'active': 0, 'disconnected': 0, 'never_connected': 0, 'pending': 0, 'total': 0}
    for agent in data['items']:
        result[agent['status']] += 1
        result['total'] += 1

    return WazuhResult(result)


@expose_resources(actions=["agent:read"], resources=["agent:id:{agent_list}"], post_proc_func=None)
def get_agents_summary_os(agent_list=None, offset=0, limit=common.database_limit, search=None, q=None):
    """Gets a list of available OS.

    :param agent_list: List of agents ID's.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param search: Looks for items with the specified string.
    :param q: Query to filter results.
    :return: WazuhResult
    """
    db_query = WazuhDBQueryDistinctAgents(offset=offset, limit=limit, search=search, select=['os.platform'],
                                          filters={'id': agent_list}, default_sort_field='os_platform', query=q,
                                          min_select_fields=set())

    return WazuhResult(db_query.run())


@expose_resources(actions=["agent:restart"], resources=["agent:id:{agent_list}"],
                  post_proc_kwargs={'exclude_codes': [1701, 1703]})
def restart_agents(agent_list=None):
    """Restarts a list of agents

    :param agent_list: List of agents ID's.
    :return: Message.
    """
    result = AffectedItemsWazuhResult(none_msg='Could not send command to any agent',
                                      all_msg='Restart command sent to all agents',
                                      some_msg='Could not send command to some agents')
    for agent_id in agent_list:
        try:
            if agent_id == "000":
                raise WazuhError(1703)
            Agent(agent_id).restart()
            result.affected_items.append(agent_id)
        except WazuhException as e:
            result.add_failed_item(id_=agent_id, error=e)

    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=["agent:read"], resources=["agent:id:{agent_list}"])
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
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    result = AffectedItemsWazuhResult(all_msg='All selected agents information is shown',
                                      some_msg='Some agents information is not shown',
                                      none_msg='No agent information is shown'
                                      )
    if len(agent_list) != 0:
        if filters is None:
            filters = dict()
        filters['id'] = agent_list

        for agent_id in agent_list:
            if agent_id not in common.system_agents.get():
                result.add_failed_item(id_=agent_id, error=WazuhError(1701))

        db_query = WazuhDBQueryAgents(offset=offset, limit=limit, sort=sort, search=search, select=select,
                                      filters=filters, query=q)
        data = db_query.run()
        result.affected_items.extend(data['items'])
        result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=["agent:read"], resources=["agent:id:{agent_list}"])
def get_agents_keys(agent_list=None):
    """Get the key of existing agents

    :param agent_list: List of agents ID's.
    :return: Agent key.
    """
    result = AffectedItemsWazuhResult(all_msg='Obtained keys for all selected agents',
                                      some_msg='Some agent keys were not obtained',
                                      none_msg='No agent keys were obtained'
                                      )
    for agent_id in agent_list:
        try:
            if agent_id not in common.system_agents.get():
                raise WazuhError(1701)
            result.affected_items.append({'id': agent_id, 'key': Agent(agent_id).get_key()})
        except WazuhException as e:
            result.add_failed_item(id_=agent_id, error=e)
    result.total_affected_items = len(result.affected_items)
    return result


@expose_resources(actions=["agent:delete"], resources=["agent:id:{agent_list}"],
                  post_proc_kwargs={'exclude_codes': [1703]})
def delete_agents(agent_list=None, backup=False, purge=False, status="all", older_than="7d"):
    """Deletes a list of agents.

    :param agent_list: List of agents ID's.
    :param backup: Create backup before removing the agent.
    :param purge: Delete definitely from key store.
    :param older_than:  Filters out disconnected agents for longer than specified. Time in seconds | "[n_days]d" |
    "[n_hours]h" | "[n_minutes]m" | "[n_seconds]s". For never_connected agents, uses the register date.
    :param status: Filters by agent status: active, disconnected or never_connected. Multiples statuses separated
    by commas.
    :return: Dictionary with affected_agents (deleted agents), timeframe applied, failed_ids if it necessary
    (agents that could not be deleted), and a message.
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

        for agent_id in agent_list:
            try:
                if agent_id == "000":
                    raise WazuhError(1703)
                elif agent_id not in common.system_agents.get():
                    raise WazuhError(1701)
                else:
                    my_agent = Agent(agent_id)
                    my_agent.load_info_from_db()
                    if agent_id not in can_purge_agents:
                        raise WazuhError(
                            1731,
                            extra_message="The agent has a status different to '{0}' or the specified time "
                                          "frame 'older_than {1}' does not apply".format(status, older_than)
                        )
                    my_agent.remove(backup, purge)
                    result.affected_items.append(agent_id)
            except WazuhException as e:
                result.add_failed_item(id_=agent_id, error=e)
        result.total_affected_items = len(result.affected_items)
        result.affected_items.sort(key=int)
        result['older_than'] = older_than

    return result


@expose_resources(actions=["agent:create"], resources=["*:*:*"], post_proc_func=None)
def add_agent(name=None, agent_id=None, key=None, ip='any', force_time=-1):
    """Adds a new Wazuh agent.

    :param name: name of the new agent.
    :param agent_id: id of the new agent.
    :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
    :param key: name of the new agent.
    :param force_time: Remove old agent with same IP if disconnected since <force_time> seconds.
    :return: Agent ID.
    """
    # Check length of agent name
    if len(name) > 128:
        raise WazuhError(1738)

    new_agent = Agent(name=name, ip=ip, id=agent_id, key=key, force=force_time)

    return WazuhResult({'id': new_agent.id, 'key': new_agent.key})


@expose_resources(actions=["group:read"], resources=["group:id:{group_list}"])
def get_groups(group_list=None, offset=0, limit=None, sort_by=None, sort_ascending=True,
               search_text=None, complementary_search=False, search_in_fields=None, hash_algorithm='md5'):
    """Gets the existing groups.

    :param group_list: List of Group names.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :param hash_algorithm: hash algorithm used to get mergedsum and configsum.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """

    # Connect DB
    db_global = glob(common.database_path_global)
    if not db_global:
        raise WazuhInternalError(1600)

    conn = Connection(db_global[0])
    affected_groups = list()
    result = AffectedItemsWazuhResult(all_msg='Obtained information about all selected groups',
                                      some_msg='Some groups information was not obtained',
                                      none_msg='No group information was obtained'
                                      )

    # Group names
    for group_id in group_list:
        try:
            # Check if the group exists
            if group_id not in group_list:
                raise WazuhError(1710)
            full_entry = path.join(common.shared_path, group_id)

            # Get the id of the group
            query = "SELECT id FROM `group` WHERE name = :group_id"
            request = {'group_id': group_id}
            conn.execute(query, request)
            id_group = conn.fetch()

            if id_group is None:
                continue

            # Group count
            query = "SELECT {0} FROM belongs WHERE id_group = :id"
            request = {'id': id_group}
            conn.execute(query.format('COUNT(*)'), request)

            # merged.mg and agent.conf sum
            merged_sum = get_hash(path.join(full_entry, "merged.mg"), hash_algorithm)
            conf_sum = get_hash(path.join(full_entry, "agent.conf"), hash_algorithm)

            item = {'count': conn.fetch(), 'name': group_id}

            if merged_sum:
                item['mergedSum'] = merged_sum

            if conf_sum:
                item['configSum'] = conf_sum

            affected_groups.append(item)
        except WazuhException as e:
            result.add_failed_item(id_=group_id, error=e)

    data = process_array(affected_groups, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by, sort_ascending=sort_ascending,
                         offset=offset, limit=limit)

    result.affected_items = data
    result.total_affected_items = len(data)

    return result


@expose_resources(actions=["group:read"], resources=["group:id:{group_list}"], post_proc_func=None)
def get_group_files(group_list=None, offset=0, limit=None, search_text=None, search_in_fields=None,
                    complementary_search=False, sort_by=None, sort_ascending=True, hash_algorithm='md5'):
    """Gets the group files.

    :param group_list: List of Group names.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :param hash_algorithm: hash algorithm used to get mergedsum and configsum.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    # We access unique group_id from list, this may change if and when we decide to add option to get files for
    # a list of groups
    group_id = group_list[0]
    group_path = common.shared_path
    if group_id:
        if not Agent.group_exists(group_id):
            raise WazuhError(1710, extra_message=group_id)
        group_path = path.join(common.shared_path, group_id)

    if not path.exists(group_path):
        raise WazuhError(1006, extra_message=group_path)

    try:
        data = []
        for entry in listdir(group_path):
            item = dict()
            try:
                item['filename'] = entry
                item['hash'] = get_hash(path.join(group_path, entry), hash_algorithm)
                data.append(item)
            except (OSError, IOError):
                pass

        try:
            # ar.conf
            ar_path = path.join(common.shared_path, 'ar.conf')
            data.append({'filename': "ar.conf", 'hash': get_hash(ar_path, hash_algorithm)})
        except (OSError, IOError):
            pass

        return WazuhResult(process_array(data, search_text=search_text, search_in_fields=search_in_fields,
                                         complementary_search=complementary_search, sort_by=sort_by,
                                         sort_ascending=sort_ascending, offset=offset, limit=limit))
    except WazuhError as e:
        raise e
    except Exception as e:
        raise WazuhInternalError(1727, extra_message=str(e))


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
        msg = "Group '{0}' created.".format(group_id)
    except Exception as e:
        raise WazuhInternalError(1005, extra_message=str(e))

    return WazuhResult({'message': msg})


@expose_resources(actions=["group:delete"], resources=["group:id:{group_list}"],
                  post_proc_kwargs={'exclude_codes': [1712]})
def delete_groups(group_list=None):
    """Delete a list of groups and remove it from every agent assignments.

    :param group_list: List of Group names.
    :return: Confirmation message.
    """
    result = AffectedItemsWazuhResult(all_msg='All selected groups were deleted',
                                      some_msg='Some groups were not deleted',
                                      none_msg='No group was deleted')
    affected_agents = set()
    for group_id in group_list:
        try:
            # Check if group exists
            if group_id not in common.system_groups.get():
                raise WazuhError(1710)
            if group_id == 'default':
                raise WazuhError(1712)
            agent_list = list(map(operator.itemgetter('id'),
                                  WazuhDBQueryMultigroups(group_id=group_id, limit=None).run()['items']))
            affected_agents_result = remove_agents_from_group(agent_list=agent_list, group_list=[group_id])
            if affected_agents_result.total_failed_items == 0:
                Agent.delete_single_group(group_id)
                result.affected_items.append(group_id)
                affected_agents.update(affected_agents_result.affected_items)
            else:
                raise WazuhError(4000)
        except WazuhException as e:
            result.add_failed_item(id_=group_id, error=e)

    result['affected_agents'] = sorted(affected_agents, key=int)
    result.affected_items.sort()
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=["group:modify_assignments"], resources=['group:id:{replace_list}'], post_proc_func=None)
@expose_resources(actions=["group:modify_assignments"], resources=['group:id:{group_list}'], post_proc_func=None)
@expose_resources(actions=["agent:modify_group"], resources=["agent:id:{agent_list}"],
                  post_proc_kwargs={'exclude_codes': [1703, 1751, 1752, 1753]})
def assign_agents_to_group(group_list=None, agent_list=None, replace=False, replace_list=None):
    """Assign a list of agents to a group

    :param group_list: List of Group names.
    :param agent_list: List of Agent IDs.
    :param replace: Whether to append new group to current agent's group or replace it.
    :param replace_list: List of Group names that can be replaced
    :return: Confirmation message.
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
        raise WazuhError(1710)

    for agent_id in agent_list:
        try:
            if agent_id not in common.system_agents.get():
                raise WazuhError(1701)
            if agent_id == "000":
                raise WazuhError(1703)
            Agent.add_group_to_agent(group_id, agent_id, force=True, replace=replace, replace_list=replace_list)
            result.affected_items.append(agent_id)
        except WazuhException as e:
            result.add_failed_item(id_=agent_id, error=e)

    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=["group:modify_assignments"], resources=['group:id:{group_list}'], post_proc_func=None)
@expose_resources(actions=["agent:modify_group"], resources=['agent:id:{agent_list}'], post_proc_func=None)
def remove_agent_from_group(group_list=None, agent_list=None):
    """Removes an agent assignment from a specified group

    :param group_list: List of Group names.
    :param agent_list: List of Agent IDs.
    :return: Confirmation message.
    """
    group_id = group_list[0]
    agent_id = agent_list[0]

    # Check if agent and group exist and it is not 000
    if agent_id not in common.system_agents.get():
        raise WazuhError(1701)
    if agent_id == '000':
        raise WazuhError(1703)
    if group_id not in common.system_groups.get():
        raise WazuhError(1710)

    return WazuhResult({'message': Agent.unset_single_group_agent(agent_id=agent_id, group_id=group_id, force=True)})


@expose_resources(actions=["agent:modify_group"], resources=["agent:id:{agent_list}"], post_proc_func=None)
@expose_resources(actions=["group:modify_assignments"], resources=["group:id:{group_list}"],
                  post_proc_kwargs={'exclude_codes': [1734, 1745]})
def remove_agent_from_groups(agent_list=None, group_list=None):
    """Removes an agent assigment from a list of groups

    :param agent_list: List of agents ID's.
    :param group_list: List of Group names.
    :return: Confirmation message.
    """
    agent_id = agent_list[0]
    result = AffectedItemsWazuhResult(all_msg='Specified agent removed from shown groups',
                                      some_msg='Specified agent could not be removed from some groups',
                                      none_msg='Specified agent could not be removed from any group'
                                      )

    # Check if agent exists and it is not 000
    if agent_id == '000':
        raise WazuhError(1703)
    if agent_id not in common.system_agents.get():
        raise WazuhError(1701)

    # We move default group to last position in case it is contained in group_list. When an agent is removed from all
    # groups it is reverted to 'default'. We try default last to avoid removing it and then adding again.
    try:
        group_list.append(group_list.pop(group_list.index('default')))
    except ValueError:
        pass

    for group_id in group_list:
        try:
            if group_id not in common.system_groups.get():
                raise WazuhError(1710)
            Agent.unset_single_group_agent(agent_id=agent_id, group_id=group_id, force=True)
            result.affected_items.append(group_id)
        except WazuhException as e:
            result.add_failed_item(id_=group_id, error=e)
    result.total_affected_items = len(result.affected_items)
    result.affected_items.sort()
    return result


@expose_resources(actions=["group:modify_assignments"], resources=["group:id:{group_list}"], post_proc_func=None)
@expose_resources(actions=["agent:modify_group"], resources=["agent:id:{agent_list}"],
                  post_proc_kwargs={'exclude_codes': [1703, 1734]})
def remove_agents_from_group(agent_list=None, group_list=None):
    """Remove a list of agents assignment from a specified group

    :param agent_list: List of agents ID's.
    :param group_list: List of Group names.
    :return: Confirmation message.
    """
    group_id = group_list[0]
    result = AffectedItemsWazuhResult(all_msg=f'All selected agents were removed from group {group_id}',
                                      some_msg=f'Some agents were not removed from group {group_id}',
                                      none_msg=f'No agent was removed from group {group_id}'
                                      )
    # Check if group exists
    if group_id not in common.system_groups.get():
        raise WazuhError(1710)

    for agent_id in agent_list:
        try:
            if agent_id == '000':
                raise WazuhError(1703)
            if agent_id not in common.system_agents.get():
                raise WazuhError(1701)
            Agent.unset_single_group_agent(agent_id=agent_id, group_id=group_id, force=True)
            result.affected_items.append(agent_id)
        except WazuhException as e:
            result.add_failed_item(id_=agent_id, error=e)
    result.total_affected_items = len(result.affected_items)
    result.affected_items.sort()

    return result


@expose_resources(actions=["agent:read"], resources=["agent:id:{agent_list}"])
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
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """

    result = AffectedItemsWazuhResult(all_msg='All selected agents information is shown',
                                      some_msg='Some agents information is not shown',
                                      none_msg='No agent information is shown'
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
    :param wpk_repo: URL for WPK download
    :param version: Version to upgrade to
    :param force: force the update even if it is a downgrade
    :param chunk_size: size of each update chunk
    :param use_http: False for HTTPS protocol, True for HTTP protocol
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
    :param timeout: Maximum time for the call to be considered failed
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
    :param file_path: Path to the installation file
    :param installer: Selected installer
    :return: Upgrade message.
    """
    if not file_path or not installer:
        raise WazuhInternalError(1307)

    # We access unique agent_id from list, this may change if and when we decide to add option to upgrade a list of
    # agents
    agent_id = agent_list[0]

    return Agent(agent_id).upgrade_custom(file_path=file_path, installer=installer)


@expose_resources(actions=["agent:read"], resources=["agent:id:{agent_list}"], post_proc_func=None)
def get_agent_config(agent_list=None, component=None, config=None):
    """Read selected configuration from agent.

    :param agent_list: List of agents ID's.
    :param component: Selected component
    :param config: Configuration to get, written on disk
    :return: WazuhResult(Loaded configuration in JSON)
    """
    # We access unique agent_id from list, this may change if and when we decide a final way to handle get responses
    # with failed ids and a list of agents
    agent_id = agent_list[0]
    my_agent = Agent(agent_id)
    my_agent.load_info_from_db()

    if my_agent.status != "active":
        raise WazuhError(1740)

    return WazuhResult(my_agent.getconfig(component=component, config=config))


@expose_resources(actions=["agent:read"], resources=["agent:id:{agent_list}"])
def get_agents_sync_group(agent_list=None):
    """Get agents configuration sync status.

    :param agent_list: List of agents ID's.
    :return Sync status
    """
    result = AffectedItemsWazuhResult(none_msg='No sync info shown.',
                                      all_msg='Sync info shown for all selected agents.',
                                      some_msg='Could not show sync info for some selected agents.')

    for agent_id in agent_list:
        try:
            if agent_id == "000":
                raise WazuhError(1703)
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
    """ Reads configuration file for specified group

    :param group_list: List of Group names.
    :param type_conf: Type of file
    :param return_format: Format of the answer (xml or json)
    :param filename: Filename to read config from.
    :return: agent.conf as dictionary.
    """
    # We access unique group_id from list, this may change if and when we decide to add option to get configuration
    # files for a list of groups
    group_id = group_list[0]

    return configuration.get_file_conf(filename, group_id=group_id, type_conf=type_conf, return_format=return_format)


@expose_resources(actions=["group:read"], resources=["group:id:{group_list}"], post_proc_func=None)
def get_agent_conf(group_list=None, filename='agent.conf'):
    """ Reads agent conf for specified group

    :param group_list: List of Group names.
    :param filename: Filename to read config from.
    :return: agent.conf as dictionary.
    """
    # We access unique group_id from list, this may change if and when we decide to add option to get agent conf for
    # a list of groups
    group_id = group_list[0]

    return configuration.get_agent_conf(group_id=group_id, filename=filename)['items']


@expose_resources(actions=["group:update_config"], resources=["group:id:{group_list}"], post_proc_func=None)
def upload_group_file(group_list=None, file_data=None, file_name='agent.conf'):
    """Updates a group file

    :param group_list: List of Group names.
    :param file_data: Relative path of temporary file to upload
    :param file_name: File name to update
    :return: Confirmation message in string
    """
    # We access unique group_id from list, this may change if and when we decide to add option to update files for
    # a list of groups
    group_id = group_list[0]

    return WazuhResult({'message': configuration.upload_group_file(group_id, file_data, file_name=file_name)})
