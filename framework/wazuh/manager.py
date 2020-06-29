# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import fcntl
import json
import re
import socket
from datetime import timezone
from os import remove
from os.path import exists, join

from wazuh import Wazuh
from wazuh.core import common, configuration
from wazuh.core.configuration import get_ossec_conf
from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.utils import manager_restart, read_cluster_config
from wazuh.core.manager import status, get_ossec_log_fields, upload_xml, upload_list, validate_xml, validate_cdb_list, \
    parse_execd_output, get_api_conf, update_api_conf
from wazuh.core.exception import WazuhError, WazuhInternalError
from wazuh.rbac.decorators import expose_resources
from wazuh.core.results import WazuhResult, AffectedItemsWazuhResult
from wazuh.utils import previous_month, tail, process_array

allowed_api_fields = {'behind_proxy_server', 'logs', 'cache', 'cors', 'use_only_authd', 'experimental_features'}
execq_lockfile = join(common.ossec_path, "var", "run", ".api_execq_lock")
cluster_enabled = not read_cluster_config()['disabled']
node_id = get_node().get('node') if cluster_enabled else 'manager'


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read_config"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def get_status():
    """Wrapper for status().

    :return: AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(all_msg=f"Processes status read successfully"
                                              f"{' in specified node' if node_id != 'manager' else ''}",
                                      some_msg='Could not read basic information in some nodes',
                                      none_msg=f"Could not read processes status"
                                               f"{' in specified node' if node_id != 'manager' else ''}"
                                      )

    result.affected_items.append(status())
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read_config"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def ossec_log(type_log='all', category='all', months=3, offset=0, limit=common.database_limit, sort_by=None,
              sort_ascending=True, search_text=None, complementary_search=False, search_in_fields=None, q=''):
    """Gets logs from ossec.log.

    :param type_log: Filters by log type: all, error or info.
    :param category: Filters by log category (i.e. ossec-remoted).
    :param months: Returns logs of the last n months. By default is 3 months.
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
    result = AffectedItemsWazuhResult(all_msg=f"Logs read successfully"
                                              f"{' in specified node' if node_id != 'manager' else ''}",
                                      some_msg='Could not read logs in some nodes',
                                      none_msg=f"Could not read logs"
                                               f"{' in specified node' if node_id != 'manager' else ''}"
                                      )
    logs = []

    first_date = previous_month(months)
    statfs_error = "ERROR: statfs('******') produced error: No such file or directory"

    for line in tail(common.ossec_log, 2000):
        log_fields = get_ossec_log_fields(line)
        if log_fields:
            log_date, log_category, level, description = log_fields

            if log_date < first_date:
                continue

            if category != 'all':
                if log_category:
                    if log_category != category:
                        continue
                else:
                    continue
            # We transform local time (ossec.log) to UTC with ISO8601 maintaining time integrity
            log_line = {'timestamp': log_date.astimezone(timezone.utc),
                        'tag': log_category, 'level': level, 'description': description}

            if type_log == 'all':
                logs.append(log_line)
            elif type_log.lower() == level.lower():
                if "ERROR: statfs(" in line:
                    if statfs_error in logs:
                        continue
                    else:
                        logs.append(statfs_error)
                else:
                    logs.append(log_line)
            else:
                continue
        else:
            if logs and line and log_category == logs[-1]['tag'] and level == logs[-1]['level']:
                logs[-1]['description'] += "\n" + line

    data = process_array(logs, search_text=search_text, search_in_fields=search_in_fields,
                         complementary_search=complementary_search, sort_by=sort_by,
                         sort_ascending=sort_ascending, offset=offset, limit=limit, q=q)
    result.affected_items.extend(data['items'])
    result.total_affected_items = data['totalItems']

    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read_config"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def ossec_log_summary(months=3):
    """ Summary of ossec.log.

    :param months: Check logs of the last n months. By default is 3 months.
    :return: AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(all_msg=f"Log summarized successfully"
                                              f"{' in specified node' if node_id != 'manager' else ''}",
                                      some_msg='Could not summarize the log in some nodes',
                                      none_msg=f"Could not summarize the log"
                                               f"{' in specified node' if node_id != 'manager' else ''}"
                                      )
    categories = dict()

    first_date = previous_month(months)

    with open(common.ossec_log, errors='ignore') as f:
        lines_count = 0
        for line in f:
            if lines_count > 50000:
                break
            lines_count = lines_count + 1

            line = get_ossec_log_fields(line)

            # Multiline logs
            if line is None:
                continue

            log_date, category, log_type, _, = line

            if log_date < first_date:
                break

            if category:
                if category in categories:
                    categories[category]['all'] += 1
                else:
                    categories[category] = {'all': 1, 'info': 0, 'error': 0, 'critical': 0, 'warning': 0, 'debug': 0}
                categories[category][log_type] += 1
            else:
                continue

    for k, v in categories.items():
        result.affected_items.append({k: v})
    result.affected_items = sorted(result.affected_items, key=lambda i: list(i.keys())[0])
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:upload_file"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def upload_file(path=None, content=None, overwrite=False):
    """Upload a new file

    :param path: Path of destination of the new file
    :param content: Content of file to be uploaded
    :param overwrite: True for updating existing files, False otherwise
    :return: AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(all_msg='File was uploaded successfully',
                                      none_msg='Could not upload file'
                                      )
    try:
        # If file already exists and overwrite is False, raise exception
        if not overwrite and exists(join(common.ossec_path, path)):
            raise WazuhError(1905)
        elif overwrite and exists(join(common.ossec_path, path)):
            delete_file(path=path)
        if len(content) == 0:
            raise WazuhError(1112)

        # For CDB lists
        if re.match(r'^etc/lists', path):
            upload_list(content, path)
        else:
            upload_xml(content, path)
        result.affected_items.append(path)
    except WazuhError as e:
        result.add_failed_item(id_=path, error=e)
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read_file"],
                  resources=[f'node:id:{node_id}&file:path:{{path}}'] if cluster_enabled else ['file:path:{path}'],
                  post_proc_func=None)
def get_file(path, validate=False):
    """Returns the content of a file.

    :param path: Relative path of file from origin
    :param validate: Whether to validate file content or not
    :return: WazuhResult
    """
    full_path = join(common.ossec_path, path[0])

    # check if file exists
    if not exists(full_path):
        raise WazuhError(1906)

    # validate CDB lists files
    if validate and re.match(r'^etc/lists', path[0]) and not validate_cdb_list(path[0]):
        raise WazuhError(1800, {'path': path[0]})

    # validate XML files
    if validate and not validate_xml(path[0]):
        raise WazuhError(1113)

    try:
        with open(full_path) as f:
            output = f.read()
    except IOError:
        raise WazuhInternalError(1005)

    return WazuhResult({'contents': output})


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:delete_file"],
                  resources=[f'node:id:{node_id}&file:path:{{path}}'] if cluster_enabled else ['file:path:{path}'])
def delete_file(path):
    """Deletes a file.

    :param path: Relative path of the file to be deleted
    :return: AffectedItemsWazuhResult
    """
    result = AffectedItemsWazuhResult(all_msg='File was deleted successfully',
                                      none_msg='Could not delete file'
                                      )

    full_path = join(common.ossec_path, path[0])

    try:
        if exists(full_path):
            try:
                remove(full_path)
                result.affected_items.append(path[0])
            except IOError:
                raise WazuhError(1907)
        else:
            raise WazuhError(1906)
    except WazuhError as e:
        result.add_failed_item(id_=path[0], error=e)
    result.total_affected_items = len(result.affected_items)

    return result


_get_config_default_result_kwargs = {
    'all_msg': f"API configuration read successfully{' in all specified nodes' if node_id != 'manager' else '' }",
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
    'all_msg': f"API configuration successfully updated{' in all specified nodes' if node_id != 'manager' else '' }. "
               f"Some settings may require restarting the API to be applied",
    'some_msg': 'Not all API configuration could be updated',
    'none_msg': f"API configuration could not be updated{' in any node' if node_id != 'manager' else ''}",
    'sort_casting': ['str']
}


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:update_api_config"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'],
                  post_proc_kwargs={'default_result_kwargs': _update_config_default_result_kwargs})
def update_api_config(updated_config=None):
    """Update or restore current API configuration.

    Update the shared configuration object "api_conf"  wih
    "updated_config" and then overwrite the content of api.yaml.

    Parameters
    ----------
    updated_config : dict
        Dictionary with the new configuration.

    Returns
    -------
    result : AffectedItemsWazuhResult
        Confirmation/Error message.
    """
    result = AffectedItemsWazuhResult(**_update_config_default_result_kwargs)

    try:
        update_api_conf(updated_config)
        result.affected_items.append(node_id)
    except WazuhError as e:
        result.add_failed_item(id_=node_id, error=e)
    result.total_affected_items = len(result.affected_items)

    return result


_restart_default_result_kwargs = {
    'all_msg': f"Restart request sent to {' all specified nodes' if node_id != ' manager' else ''}",
    'some_msg': 'Could not send restart request to some specified nodes',
    'none_msg': "No restart request sent",
    'sort_casting': ['str']
}


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
    'all_msg': f"Validation checked successfully{' in all nodes' if node_id != 'manager' else ''}",
    'some_msg': 'Could not check validation in some nodes',
    'none_msg': f"Could not check validation{' in any node' if node_id != 'manager' else ''}",
    'sort_fields': ['name'],
    'sort_casting': ['str'],
}


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read_config"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'],
                  post_proc_kwargs={'default_result_kwargs': _validation_default_result_kwargs})
def validation():
    """Check if Wazuh configuration is OK.

    :return: AffectedItemsWazuhResult.
    """
    result = AffectedItemsWazuhResult(**_validation_default_result_kwargs)

    lock_file = open(execq_lockfile, 'a+')
    fcntl.lockf(lock_file, fcntl.LOCK_EX)
    try:
        # Sockets path
        api_socket_relative_path = join('queue', 'alerts', 'execa')
        api_socket_path = join(common.ossec_path, api_socket_relative_path)
        execq_socket_path = common.EXECQ
        # Message for checking Wazuh configuration
        execq_msg = 'check-manager-configuration '

        # Remove api_socket if exists
        try:
            remove(api_socket_path)
        except OSError as e:
            if exists(api_socket_path):
                extra_msg = f'Socket: WAZUH_PATH/{api_socket_relative_path}. Error: {e.strerror}'
                raise WazuhInternalError(1014, extra_message=extra_msg)

        # up API socket
        try:
            api_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            api_socket.bind(api_socket_path)
            # Timeout
            api_socket.settimeout(5)
        except OSError as e:
            extra_msg = f'Socket: WAZUH_PATH/{api_socket_relative_path}. Error: {e.strerror}'
            raise WazuhInternalError(1013, extra_message=extra_msg)

        # Connect to execq socket
        if exists(execq_socket_path):
            try:
                execq_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
                execq_socket.connect(execq_socket_path)
            except OSError as e:
                extra_msg = f'Socket: WAZUH_PATH/queue/alerts/execq. Error {e.strerror}'
                raise WazuhInternalError(1013, extra_message=extra_msg)
        else:
            raise WazuhInternalError(1901)

        # Send msg to execq socket
        try:
            execq_socket.send(execq_msg.encode())
            execq_socket.close()
        except socket.error as e:
            raise WazuhInternalError(1014, extra_message=str(e))
        finally:
            execq_socket.close()

        # If api_socket receives a message, configuration is OK
        try:
            buffer = bytearray()
            # Receive data
            datagram = api_socket.recv(4096)
            buffer.extend(datagram)
        except socket.timeout as e:
            raise WazuhInternalError(1014, extra_message=str(e))
        finally:
            api_socket.close()
            # Remove api_socket
            if exists(api_socket_path):
                remove(api_socket_path)

        try:
            response = parse_execd_output(buffer.decode('utf-8').rstrip('\0'))
        except (KeyError, json.decoder.JSONDecodeError) as e:
            raise WazuhInternalError(1904, extra_message=str(e))

        result.affected_items.append({'name': node_id, **response})
        result.total_affected_items += 1
    except WazuhError as e:
        result.add_failed_item(id_=node_id, error=e)
    finally:
        fcntl.lockf(lock_file, fcntl.LOCK_UN)
        lock_file.close()

    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read_config"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def get_config(component=None, config=None):
    """ Wrapper for get_active_configuration

    :param component: Selected component.
    :param config: Configuration to get, written on disk.
    :return: AffectedItemsWazuhResult.
    """
    result = AffectedItemsWazuhResult(all_msg=f"Active configuration read successfully"
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


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read_config"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def read_ossec_conf(section=None, field=None):
    """ Wrapper for get_ossec_conf

    :param section: Filters by section (i.e. rules).
    :param field: Filters by field in section (i.e. included).
    :return: AffectedItemsWazuhResult.
    """
    result = AffectedItemsWazuhResult(all_msg=f"Configuration read successfully"
                                              f"{' in specified node' if node_id != 'manager' else ''}",
                                      some_msg='Could not read configuration in some nodes',
                                      none_msg=f"Could not read configuration"
                                               f"{' in specified node' if node_id != 'manager' else ''}"
                                      )

    try:
        result.affected_items.append(get_ossec_conf(section=section, field=field))
    except WazuhError as e:
        result.add_failed_item(id_=node_id, error=e)
    result.total_affected_items = len(result.affected_items)

    return result


@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read_config"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'])
def get_basic_info():
    """ Wrapper for Wazuh().to_dict

    :return: AffectedItemsWazuhResult.
    """
    result = AffectedItemsWazuhResult(all_msg=f"Basic information read successfully"
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
