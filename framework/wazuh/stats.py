# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core import common
from wazuh.core.cluster.cluster import get_node
from wazuh.core.engine_http import EngineHTTPClient
from wazuh.core.exception import WazuhException
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.stats import get_daemons_stats_socket
from wazuh.rbac.decorators import expose_resources

node_id = get_node().get('node')

@expose_resources(actions=['cluster:read'], resources=[f'node:id:{node_id}'])
def get_daemons_stats(daemons_list: list = None) -> AffectedItemsWazuhResult:
    """Get statistical information from the specified daemons.
    If the list is empty, the stats from all daemons will be retrieved.

    Parameters
    ----------
    daemons_list : list
        List of the daemons to get statistical information from.

    Returns
    -------
    AffectedItemsWazuhResult
        Dictionary with the stats of the input file.
    """
    daemon_socket_mapping = {'wazuh-manager-remoted': common.REMOTED_SOCKET,
                             'wazuh-manager-analysisd': None,
                             'wazuh-manager-db': common.WDB_SOCKET}
    result = AffectedItemsWazuhResult(all_msg='Statistical information for each daemon was successfully read',
                                      some_msg='Could not read statistical information for some daemons',
                                      none_msg='Could not read statistical information for any daemon')

    for daemon in daemons_list or daemon_socket_mapping.keys():
        try:
            if daemon == 'wazuh-manager-analysisd':
                client = EngineHTTPClient()
                try:
                    result.affected_items.append(client.get_metrics_dump())
                finally:
                    client.close()
            else:
                result.affected_items.append(get_daemons_stats_socket(daemon_socket_mapping[daemon]))
        except WazuhException as e:
            result.add_failed_item(id_=daemon, error=e)

    result.total_affected_items = len(result.affected_items)
    return result


@expose_resources(actions=['cluster:read'], resources=[f'node:id:{node_id}'])
def get_engine_metrics() -> AffectedItemsWazuhResult:
    """Fetch Engine metrics dump from the local analysisd socket.

    Returns
    -------
    AffectedItemsWazuhResult
        Engine metrics dump as the single affected item.
    """
    result = AffectedItemsWazuhResult(
        all_msg='Engine metrics were successfully retrieved',
        some_msg='Could not retrieve engine metrics',
        none_msg='Could not retrieve engine metrics',
    )

    client = None
    try:
        client = EngineHTTPClient()
        data = client.get_metrics_dump()
        result.affected_items.append(data)
    except WazuhException as e:
        result.add_failed_item(id_='engine', error=e)
    finally:
        if client is not None:
            client.close()

    result.total_affected_items = len(result.affected_items)
    return result
