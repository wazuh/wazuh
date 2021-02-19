# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from os import remove
from os.path import exists
from shutil import copyfile

from wazuh import Wazuh
from wazuh.core import common, configuration
from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.utils import manager_restart, read_cluster_config
from wazuh.core.configuration import get_ossec_conf, write_ossec_conf
from wazuh.core.exception import WazuhError
from wazuh.core.manager import status, get_api_conf, get_ossec_logs, get_logs_summary, validate_ossec_conf
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.utils import process_array, safe_move, validate_wazuh_xml
from wazuh.rbac.decorators import expose_resources

allowed_api_fields = {'behind_proxy_server', 'logs', 'cache', 'cors', 'use_only_authd', 'experimental_features'}
cluster_enabled = not read_cluster_config()['disabled']
node_id = get_node().get('node') if cluster_enabled else 'manager'


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def get_status():
    """Wrapper for status().

    :return: AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(all_msg=f"Processes status was successfully read"
                                              f"{' in specified node' if node_id != 'manager' else ''}",
                                      some_msg='Could not read basic information in some nodes',
                                      none_msg=f"Could not read processes status"
                                               f"{' in specified node' if node_id != 'manager' else ''}"
                                      )

    result.affected_items.append(status())
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def ossec_log(level=None, tag=None, offset=0, limit=common.database_limit, sort_by=None,
              sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None, q=''):
    """Gets logs from ossec.log.

    :param level: Filters by log level: all, error or info.
    :param tag: Filters by log category/tag (i.e. ossec-remoted).
    :param offset: First item to return.
    :param limit: Maximum number of items to return.
    :param sort_by: Fields to sort the items by
    :param sort_ascending: Sort in ascending (true) or descending (false) order
    :param search_text: Text to search
    :param complementary_search: Find items without the text to search
    :param search_in_fields: Fields to search in
    :param q: Defines query to filter.
    :return: AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(all_msg=f"Logs were successfully read"
                                              f"{' in specified node' if node_id != 'manager' else ''}",
                                      some_msg='Could not read logs in some nodes',
                                      none_msg=f"Could not read logs"
                                               f"{' in specified node' if node_id != 'manager' else ''}"
                                      )
    logs = get_ossec_logs()

    query = []
    level and query.append(f'level={level}')
    tag and query.append(f'tag={tag}')
    q and query.append(q)
    query = ';'.join(query)

    data = process_array(logs, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by,
                         sort_ascending=sort_ascending, offset=offset, limit=limit, q=query)
    result.affected_items.extend(data['items'])
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def ossec_log_summary():
    """Summary of ossec.log.

    :return: AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(all_msg=f"Log was successfully summarized"
                                              f"{' in specified node' if node_id != 'manager' else ''}",
                                      some_msg='Could not summarize the log in some nodes',
                                      none_msg=f"Could not summarize the log"
                                               f"{' in specified node' if node_id != 'manager' else ''}"
                                      )

    logs_summary = get_logs_summary()

    for k, v in logs_summary.items():
        result.affected_items.append({k: v})
    result.affected_items = sorted(result.affected_items, key=lambda i: list(i.keys())[0])
    result.total_affected_items = len(result.affected_items)

    return result


_get_config_default_result_kwargs = {
    'all_msg': f"API configuration was successfully read{' in all specified nodes' if node_id != 'manager' else '' }",
    'some_msg': 'Not all API configurations could be read',
    'none_msg': f"Could not read API configuration{' in any node' if node_id != 'manager' else ''}",
    'sort_casting': ['str']
}


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read_api_config"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'],
                  post_proc_kwargs={'default_result_kwargs': _get_config_default_result_kwargs})
def get_api_config():
    """Returns current API configuration.

    Returns
    -------
    result : AffectedItemsWazuhResult
        Current API configuration of the manager.
    """
    result = AffectedItemsWazuhResult(**_get_config_default_result_kwargs)

    try:
        api_config = {'node_name': node_id,
                      'node_api_config': get_api_conf()}
        result.affected_items.append(api_config)
    except WazuhError as e:
        result.add_failed_item(id_=node_id, error=e)
    result.total_affected_items = len(result.affected_items)

    return result


_update_config_default_result_kwargs = {
    'all_msg': f"API configuration was successfully updated{' in all specified nodes' if node_id != 'manager' else '' }. "
               f"Settings require restarting the API to be applied.",
    'some_msg': 'Not all API configuration could be updated.',
    'none_msg': f"API configuration could not be updated{' in any node' if node_id != 'manager' else ''}.",
    'sort_casting': ['str']
}


_restart_default_result_kwargs = {
    'all_msg': f"Restart request sent to {' all specified nodes' if node_id != ' manager' else ''}",
    'some_msg': "Could not send restart request to some specified nodes",
    'none_msg': "Could not send restart request to any node",
    'sort_casting': ['str']
}


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:restart"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'],
                  post_proc_kwargs={'default_result_kwargs': _restart_default_result_kwargs})
def restart():
    """Wrapper for 'restart_manager' function due to interdependence with cluster module and permission access. """
    result = AffectedItemsWazuhResult(**_restart_default_result_kwargs)
    try:
        manager_restart()
        result.affected_items.append(node_id)
    except WazuhError as e:
        result.add_failed_item(id_=node_id, error=e)
    result.total_affected_items = len(result.affected_items)

    return result


_validation_default_result_kwargs = {
    'all_msg': f"Validation was successfully checked{' in all nodes' if node_id != 'manager' else ''}",
    'some_msg': 'Could not check validation in some nodes',
    'none_msg': f"Could not check validation{' in any node' if node_id != 'manager' else ''}",
    'sort_fields': ['name'],
    'sort_casting': ['str'],
}


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'],
                  post_proc_kwargs={'default_result_kwargs': _validation_default_result_kwargs})
def validation():
    """Check if Wazuh configuration is OK.

    :return: AffectedItemsWazuhResult.
    """
    result = AffectedItemsWazuhResult(**_validation_default_result_kwargs)

    try:
        response = validate_ossec_conf()
        result.affected_items.append({'name': node_id, **response})
        result.total_affected_items += 1
    except WazuhError as e:
        result.add_failed_item(id_=node_id, error=e)

    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def get_config(component=None, config=None):
    """ Wrapper for get_active_configuration

    :param component: Selected component.
    :param config: Configuration to get, written on disk.
    :return: AffectedItemsWazuhResult.
    """
    result = AffectedItemsWazuhResult(all_msg=f"Active configuration was successfully read"
                                              f"{' in specified node' if node_id != 'manager' else ''}",
                                      some_msg='Could not read active configuration in some nodes',
                                      none_msg=f"Could not read active configuration"
                                               f"{' in specified node' if node_id != 'manager' else ''}"
                                      )

    try:
        data = configuration.get_active_configuration(agent_id='000', component=component, configuration=config)
        len(data.keys()) > 0 and result.affected_items.append(data)
    except WazuhError as e:
        result.add_failed_item(id_=node_id, error=e)
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def read_ossec_conf(section=None, field=None, raw=False):
    """ Wrapper for get_ossec_conf

    :param section: Filters by section (i.e. rules).
    :param field: Filters by field in section (i.e. included).
    :return: AffectedItemsWazuhResult.
    """
    result = AffectedItemsWazuhResult(all_msg=f"Configuration was successfully read"
                                              f"{' in specified node' if node_id != 'manager' else ''}",
                                      some_msg='Could not read configuration in some nodes',
                                      none_msg=f"Could not read configuration"
                                               f"{' in specified node' if node_id != 'manager' else ''}"
                                      )

    try:
        if raw:
            with open(common.ossec_conf) as f:
                return f.read()
        result.affected_items.append(get_ossec_conf(section=section, field=field))
    except WazuhError as e:
        result.add_failed_item(id_=node_id, error=e)
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def get_basic_info():
    """ Wrapper for Wazuh().to_dict

    :return: AffectedItemsWazuhResult.
    """
    result = AffectedItemsWazuhResult(all_msg=f"Basic information was successfully read"
                                              f"{' in specified node' if node_id != 'manager' else ''}",
                                      some_msg='Could not read basic information in some nodes',
                                      none_msg=f"Could not read basic information"
                                               f"{' in specified node' if node_id != 'manager' else ''}"
                                      )

    try:
        result.affected_items.append(Wazuh().to_dict())
    except WazuhError as e:
        result.add_failed_item(id_=node_id, error=e)
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:update_config"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def update_ossec_conf(new_conf=None):
    """
    Replace wazuh configuration (ossec.conf) with the provided configuration.

    Parameters
    ----------
    new_conf: str
        The new configuration to be applied.
    """
    result = AffectedItemsWazuhResult(all_msg=f"Configuration was successfully updated"
                                              f"{' in specified node' if node_id != 'manager' else ''}",
                                      some_msg='Could not update configuration in some nodes',
                                      none_msg=f"Could not update configuration"
                                               f"{' in specified node' if node_id != 'manager' else ''}"
                                      )
    backup_file = f'{common.ossec_conf}.backup'
    try:
        # Check a configuration has been provided
        if not new_conf:
            raise WazuhError(1125)

        # Check if the configuration is valid
        validate_wazuh_xml(new_conf, config_file=True)

        # Create a backup of the current configuration before attempting to replace it
        try:
            copyfile(common.ossec_conf, backup_file)
        except IOError:
            raise WazuhError(1019)

        # Write the new configuration and validate it
        write_ossec_conf(new_conf)
        is_valid = validate_ossec_conf()

        if not isinstance(is_valid, dict) or ('status' in is_valid and is_valid['status'] != 'OK'):
            raise WazuhError(1125)
        else:
            result.affected_items.append(node_id)
        exists(backup_file) and remove(backup_file)
    except WazuhError as e:
        result.add_failed_item(id_=node_id, error=e)
    finally:
        exists(backup_file) and safe_move(backup_file, common.ossec_conf)

    result.total_affected_items = len(result.affected_items)
    return result
