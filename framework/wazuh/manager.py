# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh import Wazuh
from wazuh.core import common
from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.utils import manager_restart
from wazuh.core.exception import WazuhError, WazuhInternalError
from wazuh.core.manager import status, get_update_information_template, get_ossec_logs, \
    get_logs_summary, validate_ossec_conf, OSSEC_LOG_FIELDS
from wazuh.core.results import AffectedItemsWazuhResult, WazuhResult
from wazuh.core.utils import process_array
from wazuh.rbac.decorators import expose_resources

node_id = get_node().get('node')


@expose_resources(actions=['cluster:read'],
                  resources=[f'node:id:{node_id}'])
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


@expose_resources(actions=['cluster:read'],
                  resources=[f'node:id:{node_id}'])
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


@expose_resources(actions=['cluster:read'],
                  resources=[f'node:id:{node_id}'])
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


_restart_default_result_kwargs = {
    'all_msg': f"Restart request sent to {'all specified nodes' if node_id != 'manager' else ''}",
    'some_msg': "Could not send restart request to some specified nodes",
    'none_msg': "Could not send restart request to any node",
    'sort_casting': ['str']
}


@expose_resources(actions=['cluster:read'],
                  resources=[f'node:id:{node_id}'])
@expose_resources(actions=['cluster:restart'],
                  resources=[f'node:id:{node_id}'],
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


@expose_resources(actions=['cluster:read'],
                  resources=[f'node:id:{node_id}'],
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


# TODO(26555): Adapt function to the new configuration
@expose_resources(actions=['cluster:read'],
                  resources=[f'node:id:{node_id}'])
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
    result = AffectedItemsWazuhResult(all_msg='This feature will be replaced or deleted by new centralized config',
                                      some_msg='This feature will be replaced or deleted by new centralized config',
                                      none_msg='This feature will be replaced or deleted by new centralized config')

    return result


@expose_resources(actions=['cluster:read'],
                  resources=[f'node:id:{node_id}'])
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


# TODO(26555): Adapt function to the new configuration
@expose_resources(actions=['cluster:update_config'],
                  resources=[f'node:id:{node_id}'])
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
    result = AffectedItemsWazuhResult(all_msg='This feature will be replaced or deleted by new centralized config',
                                      some_msg='This feature will be replaced or deleted by new centralized config',
                                      none_msg='This feature will be replaced or deleted by new centralized config')
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
