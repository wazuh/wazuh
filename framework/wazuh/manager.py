# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from os import remove
from os.path import exists

from wazuh import Wazuh
from wazuh.core import common, configuration
from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.utils import manager_restart, read_cluster_config
from wazuh.core.configuration import get_ossec_conf, write_ossec_conf
from wazuh.core.exception import WazuhError, WazuhInternalError
from wazuh.core.manager import status, get_api_conf, get_update_information_template, get_ossec_logs, \
    get_logs_summary, validate_ossec_conf, OSSEC_LOG_FIELDS
from wazuh.core.results import AffectedItemsWazuhResult, WazuhResult
from wazuh.core.utils import process_array, safe_move, validate_wazuh_xml, full_copy
from wazuh.rbac.decorators import expose_resources

cluster_enabled = not read_cluster_config(from_import=True)['disabled']
node_id = get_node().get('node') if cluster_enabled else 'manager'


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def get_status() -> AffectedItemsWazuhResult:
    """Wrapper for status().

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
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
def ossec_log(level: str = None, tag: str = None, offset: int = 0, limit: int = common.DATABASE_LIMIT,
              sort_by: dict = None, sort_ascending: bool = True, search_text: str = None,
              complementary_search: bool = False, search_in_fields: list = None,
              q: str = '', select: str = None, distinct: bool = False) -> AffectedItemsWazuhResult:
    """Get logs from ossec.log.

    Parameters
    ----------
    offset : int
        First element to return in the collection.
    limit : int
        Maximum number of elements to return.
    tag : str
        Filters by category/tag of log.
    level : str
        Filters by log level.
    sort_by : dict
        Fields to sort the items by. Format: {"fields":["field1","field2"],"order":"asc|desc"}
    sort_ascending : bool
        Sort in ascending (true) or descending (false) order.
    search_text : str
        Text to search.
    complementary_search : bool
        Find items without the text to search.
    search_in_fields : list
        Fields to search in.
    q : str
        Query to filter results by.
    select : str
        Select which fields to return (separated by comma).
    distinct : bool
        Look for distinct values.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
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
                         sort_ascending=sort_ascending, offset=offset, limit=limit, q=query,
                         select=select, allowed_select_fields=OSSEC_LOG_FIELDS, distinct=distinct)
    result.affected_items.extend(data['items'])
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def ossec_log_summary() -> AffectedItemsWazuhResult:
    """Summary of ossec.log.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
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
    'all_msg': f"API configuration was successfully read{' in all specified nodes' if node_id != 'manager' else ''}",
    'some_msg': 'Not all API configurations could be read',
    'none_msg': f"Could not read API configuration{' in any node' if node_id != 'manager' else ''}",
    'sort_casting': ['str']
}


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read_api_config"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'],
                  post_proc_kwargs={'default_result_kwargs': _get_config_default_result_kwargs})
def get_api_config() -> AffectedItemsWazuhResult:
    """Return current API configuration.

    Returns
    -------
    AffectedItemsWazuhResult
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
    'all_msg': f"API configuration was successfully updated{' in all specified nodes' if node_id != 'manager' else ''}. "
               f"Settings require restarting the API to be applied.",
    'some_msg': 'Not all API configuration could be updated.',
    'none_msg': f"API configuration could not be updated{' in any node' if node_id != 'manager' else ''}.",
    'sort_casting': ['str']
}

_restart_default_result_kwargs = {
    'all_msg': f"Restart request sent to {'all specified nodes' if node_id != 'manager' else ''}",
    'some_msg': "Could not send restart request to some specified nodes",
    'none_msg': "Could not send restart request to any node",
    'sort_casting': ['str']
}


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:restart"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'],
                  post_proc_kwargs={'default_result_kwargs': _restart_default_result_kwargs})
def restart() -> AffectedItemsWazuhResult:
    """Wrapper for 'restart_manager' function due to interdependence with cluster module and permission access.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
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
def validation() -> AffectedItemsWazuhResult:
    """Check if Wazuh configuration is OK.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
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
def get_config(component: str = None, config: str = None) -> AffectedItemsWazuhResult:
    """Wrapper for get_active_configuration.

    Parameters
    ----------
    component : str
        Selected component.
    config : str
        Configuration to get, written on disk.


    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
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
def read_ossec_conf(section: str = None, field: str = None, raw: bool = False,
                    distinct: bool = False) -> AffectedItemsWazuhResult:
    """Wrapper for get_ossec_conf.

    Parameters
    ----------
    section : str
        Filters by section (i.e. rules).
    field : str
        Filters by field in section (i.e. included).
    raw : bool
        Whether to return the file content in raw or JSON format.
    distinct : bool
        Look for distinct values.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    result = AffectedItemsWazuhResult(all_msg=f"Configuration was successfully read"
                                              f"{' in specified node' if node_id != 'manager' else ''}",
                                      some_msg='Could not read configuration in some nodes',
                                      none_msg=f"Could not read configuration"
                                               f"{' in specified node' if node_id != 'manager' else ''}"
                                      )

    try:
        if raw:
            with open(common.OSSEC_CONF) as f:
                return f.read()
        result.affected_items.append(get_ossec_conf(section=section, field=field, distinct=distinct))
    except WazuhError as e:
        result.add_failed_item(id_=node_id, error=e)
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def get_basic_info() -> AffectedItemsWazuhResult:
    """Wrapper for Wazuh().to_dict

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
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
def update_ossec_conf(new_conf: str = None) -> AffectedItemsWazuhResult:
    """Replace wazuh configuration (ossec.conf) with the provided configuration.

    Parameters
    ----------
    new_conf: str
        The new configuration to be applied.

    Returns
    -------
    AffectedItemsWazuhResult
        Affected items.
    """
    result = AffectedItemsWazuhResult(all_msg=f"Configuration was successfully updated"
                                              f"{' in specified node' if node_id != 'manager' else ''}",
                                      some_msg='Could not update configuration in some nodes',
                                      none_msg=f"Could not update configuration"
                                               f"{' in specified node' if node_id != 'manager' else ''}"
                                      )
    backup_file = f'{common.OSSEC_CONF}.backup'
    try:
        # Check a configuration has been provided
        if not new_conf:
            raise WazuhError(1125)

        # Check if the configuration is valid
        validate_wazuh_xml(new_conf, config_file=True)

        # Create a backup of the current configuration before attempting to replace it
        try:
            full_copy(common.OSSEC_CONF, backup_file)
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
        exists(backup_file) and safe_move(backup_file, common.OSSEC_CONF)

    result.total_affected_items = len(result.affected_items)
    return result


def get_update_information(installation_uid: str, update_information: dict) -> WazuhResult:
    """Process update information into a wazuh result.

    Parameters
    ----------
    installation_uid : str
        Wazuh UID to include in the result.
    update_information : dict
        Data to process.

    Returns
    -------
    WazuhResult
        Result with update information.
    """

    if not update_information:
        # Return a response with minimal data because the update_check is disabled
        return WazuhResult({'data': get_update_information_template(uuid=installation_uid, update_check=False)})
    status_code = update_information.pop('status_code')
    uuid = update_information.get('uuid')
    tag = update_information.get('current_version')

    if status_code != 200:
        extra_message = f"{uuid}, {tag}" if status_code == 401 else update_information['message']
        raise WazuhInternalError(2100, extra_message=extra_message)

    update_information.pop('message', None)

    return WazuhResult({'data': update_information})
