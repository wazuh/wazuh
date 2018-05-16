#!/usr/bin/env python

# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.utils import execute, cut_array, sort_array, search_array, chown_r, chmod_r, create_exception_dic, plain_dict_to_nested_dict
from wazuh.exception import WazuhException
from wazuh import common
from wazuh.InputValidator import InputValidator
from wazuh.database import Connection
from wazuh.agent import Agent
from wazuh.configuration import get_file_conf_path, get_agent_conf_from_path
from os import path, listdir, chmod, chown
from shutil import move, copytree
from time import time
from glob import glob
import hashlib
from operator import setitem
from pwd import getpwnam
from grp import getgrnam


def _remove_single_group(group_id):
    """
    Remove the group in every agent.

    :param group_id: Group ID.
    :return: Confirmation message.
    """

    if group_id.lower() == "default":
        raise WazuhException(1712)

    if not group_exists(group_id):
        raise WazuhException(1710, group_id)

    ids = []

    # Remove agent group
    agents = get_agent_group(group_id=group_id, limit=None)
    for agent in agents['items']:
        unset_group(agent['id'])
        ids.append(agent['id'])

    # Remove group directory
    group_path = "{0}/{1}".format(common.shared_path, group_id)
    group_backup = "{0}/groups/{1}_{2}".format(common.backup_path, group_id, int(time()))
    if path.exists(group_path):
        move(group_path, group_backup)

    msg = "Group '{0}' removed.".format(group_id)

    return {'msg': msg, 'affected_agents': ids}


def get_all_groups_sql(offset=0, limit=common.database_limit, sort=None, search=None):
    """
    Gets the existing groups.

    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """

    # Connect DB
    db_global = glob(common.database_path_global)
    if not db_global:
        raise WazuhException(1600)

    conn = Connection(db_global[0])

    # Init query
    query = "SELECT DISTINCT {0} FROM agent WHERE `group` IS NOT null"
    fields = {'name': 'group'}  # field: db_column
    select = ["`group`"]
    request = {}

    # Search
    if search:
        query += " AND NOT" if bool(search['negation']) else ' AND'
        query += " ( `group` LIKE :search )"
        request['search'] = '%{0}%'.format(search['value'])

    # Count
    conn.execute(query.format('COUNT(DISTINCT `group`)'), request)
    data = {'totalItems': conn.fetch()[0]}

    # Sorting
    if sort:
        if sort['fields']:
            allowed_sort_fields = fields.keys()
            # Check if every element in sort['fields'] is in allowed_sort_fields.
            if not set(sort['fields']).issubset(allowed_sort_fields):
                raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.format(allowed_sort_fields, sort['fields']))

            order_str_fields = ['`{0}` {1}'.format(fields[i], sort['order']) for i in sort['fields']]
            query += ' ORDER BY ' + ','.join(order_str_fields)
        else:
            query += ' ORDER BY `group` {0}'.format(sort['order'])
    else:
        query += ' ORDER BY `group` ASC'

    # OFFSET - LIMIT
    if limit:
        query += ' LIMIT :offset,:limit'
        request['offset'] = offset
        request['limit'] = limit

    # Data query
    conn.execute(query.format(','.join(select)), request)

    data['items'] = []

    for tuple in conn:
        if tuple[0] != None:
            data['items'].append(tuple[0])

    return data


def get_all_groups(offset=0, limit=common.database_limit, sort=None, search=None, hash_algorithm='md5'):
    """
    Gets the existing groups.

    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """
    def get_hash(file, hash_algorithm='md5'):
        filename = "{0}/{1}".format(common.shared_path, file)

        # check hash algorithm
        try:
            algorithm_list = hashlib.algorithms_available
        except Exception as e:
            algorithm_list = hashlib.algorithms

        if not hash_algorithm in algorithm_list:
            raise WazuhException(1723, "Available algorithms are {0}.".format(algorithm_list))

        hashing = hashlib.new(hash_algorithm)

        try:
            with open(filename, 'rb') as f:
                hashing.update(f.read())
        except IOError:
            return None

        return hashing.hexdigest()

    # Connect DB
    db_global = glob(common.database_path_global)
    if not db_global:
        raise WazuhException(1600)

    conn = Connection(db_global[0])
    query = "SELECT {0} FROM agent WHERE `group` = :group_id"

    # Group names
    data = []
    for entry in listdir(common.shared_path):
        full_entry = path.join(common.shared_path, entry)
        if not path.isdir(full_entry):
            continue

        # Group count
        request = {'group_id': entry}
        conn.execute(query.format('COUNT(*)'), request)

        # merged.mg and agent.conf sum
        merged_sum = get_hash(entry + "/merged.mg")
        conf_sum   = get_hash(entry + "/agent.conf")

        item = {'count':conn.fetch()[0], 'name': entry}

        if merged_sum:
            item['merged_sum'] = merged_sum

        if conf_sum:
            item['conf_sum'] = conf_sum

        data.append(item)


    if search:
        data = search_array(data, search['value'], search['negation'], fields=['name'])

    if sort:
        data = sort_array(data, sort['fields'], sort['order'])
    else:
        data = sort_array(data, ['name'])

    return {'items': cut_array(data, offset, limit), 'totalItems': len(data)}


def group_exists_sql(group_id):
    """
    Checks if the group exists

    :param group_id: Group ID.
    :return: True if group exists, False otherwise
    """
    # Input Validation of group_id
    if not InputValidator().group(group_id):
        raise WazuhException(1722)

    db_global = glob(common.database_path_global)
    if not db_global:
        raise WazuhException(1600)

    conn = Connection(db_global[0])

    query = "SELECT `group` FROM agent WHERE `group` = :group_id LIMIT 1"
    request = {'group_id': group_id}

    conn.execute(query, request)

    for tuple in conn:

        if tuple[0] != None:
            return True
        else:
            return False


def group_exists(group_id):
    """
    Checks if the group exists

    :param group_id: Group ID.
    :return: True if group exists, False otherwise
    """
    # Input Validation of group_id
    if not InputValidator().group(group_id):
        raise WazuhException(1722)

    if path.exists("{0}/{1}".format(common.shared_path, group_id)):
        return True
    else:
        return False


def get_agent_group(group_id, offset=0, limit=common.database_limit, sort=None, search=None, select=None):
    """
    Gets the agents in a group

    :param group_id: Group ID.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """

    # Connect DB
    db_global = glob(common.database_path_global)
    if not db_global:
        raise WazuhException(1600)

    conn = Connection(db_global[0])
    valid_select_fiels = {"id", "name", "ip", "last_keepalive", "os_name",
                         "os_version", "os_platform", "os_uname", "version",
                         "config_sum", "merged_sum", "manager_host", "status"}
    # fields like status need to retrieve others to be properly computed.
    dependent_select_fields = {'status': {'last_keepalive','version'}}
    search_fields = {"id", "name", "os_name"}

    # Init query
    query = "SELECT {0} FROM agent WHERE `group` = :group_id"
    request = {'group_id': group_id}

    # Select
    if select:
        select_fields_param = set(select['fields'])

        if not select_fields_param.issubset(valid_select_fiels):
            uncorrect_fields = select_fields_param - valid_select_fiels
            raise WazuhException(1724, "Allowed select fields: {0}. Fields {1}".\
                    format(', '.join(list(valid_select_fiels)), ', '.join(uncorrect_fields)))

        select_fields = select_fields_param
    else:
        select_fields = valid_select_fiels

    # add dependent select fields to the database select query
    db_select_fields = set()
    for dependent, dependent_fields in dependent_select_fields.items():
        if dependent in select_fields:
            db_select_fields |= dependent_fields
    db_select_fields |= (select_fields - set(dependent_select_fields.keys()))

    # Search
    if search:
        query += " AND NOT" if bool(search['negation']) else ' AND'
        query += " (" + " OR ".join(x + ' LIKE :search' for x in search_fields) + " )"
        request['search'] = '%{0}%'.format(int(search['value']) if search['value'].isdigit()
                                                                else search['value'])

    # Count
    conn.execute(query.format('COUNT(*)'), request)
    data = {'totalItems': conn.fetch()[0]}

    # Sorting
    if sort:
        if sort['fields']:
            allowed_sort_fields = db_select_fields
            # Check if every element in sort['fields'] is in allowed_sort_fields.
            if not set(sort['fields']).issubset(allowed_sort_fields):
                raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.\
                    format(allowed_sort_fields, sort['fields']))

            order_str_fields = ['{0} {1}'.format(i, sort['order']) for i in sort['fields']]
            query += ' ORDER BY ' + ','.join(order_str_fields)
        else:
            query += ' ORDER BY id {0}'.format(sort['order'])
    else:
        query += ' ORDER BY id ASC'

    # OFFSET - LIMIT
    if limit:
        query += ' LIMIT :offset,:limit'
        request['offset'] = offset
        request['limit'] = limit

    # Data query
    conn.execute(query.format(','.join(db_select_fields)), request)

    non_nested = [{field:tuple_elem for field,tuple_elem \
            in zip(db_select_fields, tuple) if tuple_elem} for tuple in conn]

    if 'id' in select_fields:
        map(lambda x: setitem(x, 'id', str(x['id']).zfill(3)), non_nested)

    if 'status' in select_fields:
        try:
            map(lambda x: setitem(x, 'status', Agent.calculate_status(x['last_keepalive'], x['version'] == None)), non_nested)
        except KeyError:
            pass

    # return only the fields requested by the user (saved in select_fields) and not the dependent ones
    non_nested = [{k:v for k,v in d.items() if k in select_fields} for d in non_nested]

    data['items'] = [plain_dict_to_nested_dict(d, ['os']) for d in non_nested]

    return data


def get_agents_without_group(offset=0, limit=common.database_limit, sort=None, search=None, select=None):
    """
    Gets the agents in a group

    :param group_id: Group ID.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """

    # Connect DB
    db_global = glob(common.database_path_global)
    if not db_global:
        raise WazuhException(1600)

    conn = Connection(db_global[0])
    valid_select_fiels = {"id", "name", "ip", "last_keepalive", "os_name",
                         "os_version", "os_platform", "os_uname", "version",
                         "config_sum", "merged_sum", "manager_host", "status"}
    # fields like status need to retrieve others to be properly computed.
    dependent_select_fields = {'status': {'last_keepalive','version'}}
    search_fields = {"id", "name", "os_name"}

    # Init query
    query = "SELECT {0} FROM agent WHERE `group` IS NULL AND id != 0"
    fields = {'id': 'id', 'name': 'name'}  # field: db_column
    request = {}

    # Select
    if select:
        select_fields_param = set(select['fields'])

        if not select_fields_param.issubset(valid_select_fiels):
            uncorrect_fields = select_fields_param - valid_select_fiels
            raise WazuhException(1724, "Allowed select fields: {0}. Fields {1}".\
                    format(', '.join(list(valid_select_fiels)), ', '.join(uncorrect_fields)))

        select_fields = select_fields_param
    else:
        select_fields = valid_select_fiels

    # add dependent select fields to the database select query
    db_select_fields = set()
    for dependent, dependent_fields in dependent_select_fields.items():
        if dependent in select_fields:
            db_select_fields |= dependent_fields
    db_select_fields |= (select_fields - set(dependent_select_fields.keys()))

    # Search
    if search:
        query += " AND NOT" if bool(search['negation']) else ' AND'
        query += " (" + " OR ".join(x + ' LIKE :search' for x in search_fields) + " )"
        request['search'] = '%{0}%'.format(int(search['value']) if search['value'].isdigit()
                                                                else search['value'])

    # Count
    conn.execute(query.format('COUNT(*)'), request)
    data = {'totalItems': conn.fetch()[0]}

    # Sorting
    if sort:
        if sort['fields']:
            allowed_sort_fields = db_select_fields
            # Check if every element in sort['fields'] is in allowed_sort_fields.
            if not set(sort['fields']).issubset(allowed_sort_fields):
                raise WazuhException(1403, 'Allowed sort fields: {0}. Fields: {1}'.\
                    format(allowed_sort_fields, sort['fields']))

            order_str_fields = ['{0} {1}'.format(fields[i], sort['order']) for i in sort['fields']]
            query += ' ORDER BY ' + ','.join(order_str_fields)
        else:
            query += ' ORDER BY id {0}'.format(sort['order'])
    else:
        query += ' ORDER BY id ASC'

    # OFFSET - LIMIT
    if limit:
        query += ' LIMIT :offset,:limit'
        request['offset'] = offset
        request['limit'] = limit

    # Data query
    conn.execute(query.format(','.join(db_select_fields)), request)

    non_nested = [{field:tuple_elem for field,tuple_elem \
            in zip(db_select_fields, tuple) if tuple_elem} for tuple in conn]

    if 'id' in select_fields:
        map(lambda x: setitem(x, 'id', str(x['id']).zfill(3)), non_nested)

    if 'status' in select_fields:
        try:
            map(lambda x: setitem(x, 'status', Agent.calculate_status(x['last_keepalive'], x['version'] == None)), non_nested)
        except KeyError:
            pass

    # return only the fields requested by the user (saved in select_fields) and not the dependent ones
    non_nested = [{k:v for k,v in d.items() if k in select_fields} for d in non_nested]

    data['items'] = [plain_dict_to_nested_dict(d, ['os']) for d in non_nested]

    return data


def get_group_files(group_id=None, offset=0, limit=common.database_limit, sort=None, search=None):
    """
    Gets the group files.

    :param group_id: Group ID.
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
    :param search: Looks for items with the specified string.
    :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
    """

    group_path = common.shared_path
    if group_id:
        if not group_exists(group_id):
            raise WazuhException(1710, group_id)
        group_path = "{0}/{1}".format(common.shared_path, group_id)

    if not path.exists(group_path):
        raise WazuhException(1006, group_path)

    try:
        data = []
        for entry in listdir(group_path):
            item = {}
            try:
                item['filename'] = entry
                with open("{0}/{1}".format(group_path, entry), 'rb') as f:
                    item['hash'] = hashlib.md5(f.read()).hexdigest()
                data.append(item)
            except (OSError, IOError) as e:
                pass

        try:
            # ar.conf
            ar_path = "{0}/ar.conf".format(common.shared_path, entry)
            with open(ar_path, 'rb') as f:
                hash_ar = hashlib.md5(f.read()).hexdigest()
            data.append({'filename': "ar.conf", 'hash': hash_ar})
        except (OSError, IOError) as e:
            pass

        if search:
            data = search_array(data, search['value'], search['negation'])

        if sort:
            data = sort_array(data, sort['fields'], sort['order'])
        else:
            data = sort_array(data, ["filename"])

        return {'items': cut_array(data, offset, limit), 'totalItems': len(data)}
    except Exception as e:
        raise WazuhException(1727, str(e))


def create_group(group_id):
    """
    Creates a group.

    :param group_id: Group ID.
    :return: Confirmation message.
    """
    # Input Validation of group_id
    if not InputValidator().group(group_id):
        raise WazuhException(1722)

    group_path = "{0}/{1}".format(common.shared_path, group_id)

    if group_id.lower() == "default" or path.exists(group_path):
        raise WazuhException(1711, group_id)

    # Create group in /etc/shared
    group_def_path = "{0}/default".format(common.shared_path)
    try:
        copytree(group_def_path, group_path)
        chown_r(group_path, common.ossec_uid, common.ossec_gid)
        chmod_r(group_path, 0o660)
        chmod(group_path, 0o770)
        msg = "Group '{0}' created.".format(group_id)
    except Exception as e:
        raise WazuhException(1005, str(e))

    return msg



def remove_group(group_id):
    """
    Remove the group in every agent.

    :param group_id: Group ID.
    :return: Confirmation message.
    """

    # Input Validation of group_id
    if not InputValidator().group(group_id):
        raise WazuhException(1722)


    failed_ids = []
    ids = []
    affected_agents = []
    if isinstance(group_id, list):
        for id in group_id:

            if id.lower() == "default":
                raise WazuhException(1712)

            try:
                removed = _remove_single_group(id)
                ids.append(id)
                affected_agents += removed['affected_agents']
            except Exception as e:
                failed_ids.append(create_exception_dic(id, e))
    else:
        if group_id.lower() == "default":
            raise WazuhException(1712)

        try:
            removed = _remove_single_group(group_id)
            ids.append(group_id)
            affected_agents += removed['affected_agents']
        except Exception as e:
            failed_ids.append(create_exception_dic(group_id, e))

    final_dict = {}
    if not failed_ids:
        message = 'All selected groups were removed'
        final_dict = {'msg': message, 'ids': ids, 'affected_agents': affected_agents}
    else:
        message = 'Some groups were not removed'
        final_dict = {'msg': message, 'failed_ids': failed_ids, 'ids': ids, 'affected_agents': affected_agents}

    return final_dict


def set_group(agent_id, group_id, force=False):
    """
    Set a group to an agent.

    :param agent_id: Agent ID.
    :param group_id: Group ID.
    :param force: No check if agent exists
    :return: Confirmation message.
    """
    # Input Validation of group_id
    if not InputValidator().group(group_id):
        raise WazuhException(1722)

    agent_id = agent_id.zfill(3)
    if agent_id == "000":
        raise WazuhException(1703)

    # Check if agent exists
    if not force:
        Agent(agent_id).get_basic_information()

    # Assign group in /queue/agent-groups
    agent_group_path = "{0}/{1}".format(common.groups_path, agent_id)
    try:
        new_file = False if path.exists(agent_group_path) else True

        f_group = open(agent_group_path, 'w')
        f_group.write(group_id)
        f_group.close()

        if new_file:
            chown(agent_group_path, common.ossec_uid, common.ossec_gid)
            chmod(agent_group_path, 0o660)
    except Exception as e:
        raise WazuhException(1005, str(e))

    # Create group in /etc/shared
    if not group_exists(group_id):
        create_group(group_id)

    return "Group '{0}' set to agent '{1}'.".format(group_id, agent_id)


def unset_group(agent_id, force=False):
    """
    Unset the agent group. The group will be 'default'.

    :param agent_id: Agent ID.
    :param force: No check if agent exists
    :return: Confirmation message.
    """
    # Check if agent exists
    if not force:
        Agent(agent_id).get_basic_information()

    agent_group_path = "{0}/{1}".format(common.groups_path, agent_id)
    if path.exists(agent_group_path):
        with open(agent_group_path, "w+") as fo:
            fo.write("default")

    return "Group unset for agent '{0}'.".format(agent_id)


def get_file_conf(filename, group_id=None, type_conf=None):
    """
    Returns the configuration file as dictionary.

    :return: configuration file as dictionary.
    """

    if group_id:
        if not group_exists(group_id):
            raise WazuhException(1710, group_id)

        file_path = "{0}/{1}".format(common.shared_path, filename) \
                    if filename == 'ar.conf' else \
                    "{0}/{1}/{2}".format(common.shared_path, group_id, filename)
    else:
        file_path = "{0}/{1}".format(common.shared_path, filename)

    return get_file_conf_path(filename, file_path, type_conf)


def get_agent_conf(group_id=None, offset=0, limit=common.database_limit, filename=None):
    """
    Returns agent.conf as dictionary.

    :return: agent.conf as dictionary.
    """
    agent_conf = ""
    if group_id:
        if not group_exists(group_id):
            raise WazuhException(1710, group_id)

        agent_conf = "{0}/{1}".format(common.shared_path, group_id)

    return get_agent_conf_from_path(agent_conf, offset, limit, filename)
