# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh.core.cluster import local_client
from wazuh.core.analysis import send_reload_ruleset_and_get_results
from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.control import set_reload_ruleset_flag
from wazuh.core.cluster.utils import read_cluster_config
from wazuh.core.exception import WazuhError
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.rbac.decorators import expose_resources, async_list_handler

cluster_enabled = not read_cluster_config(from_import=True)['disabled']
node_id = get_node().get('node') if cluster_enabled else 'manager'
node_type = get_node().get('type') if cluster_enabled else 'master'

_reload_ruleset_default_result_kwargs = {
    'all_msg': f"Reload request sent to {'all specified nodes' if node_id != 'manager' else ''}",
    'some_msg': "Could not send reload request to some specified nodes",
    'none_msg': "Could not send reload request to any node",
    'sort_casting': ['str']
}

@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:read"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'],
                  post_proc_func=async_list_handler)
@expose_resources(actions=[f"{'cluster' if cluster_enabled else 'manager'}:restart"],
                  resources=[f'node:id:{node_id}' if cluster_enabled else '*:*:*'],
                  post_proc_kwargs={'default_result_kwargs': _reload_ruleset_default_result_kwargs},
                  post_proc_func=async_list_handler)
async def reload_ruleset() -> AffectedItemsWazuhResult:
    """Reload the ruleset on the current node.

    Returns
    -------
    AffectedItemsWazuhResult
        Result of the reload operation, including affected and failed items.
    """
    results = AffectedItemsWazuhResult(**_reload_ruleset_default_result_kwargs)

    try:
        if node_type == 'master':
            results = send_reload_ruleset_and_get_results(node_id=node_id, results=results)
        else:
            lc = local_client.LocalClient()
            result = await set_reload_ruleset_flag(lc)

            if isinstance(result, dict) and 'success' in result:
                result = result['success']
                if result:
                    result = 'Ruleset reload request sent successfully.'
                else:
                    result = 'Failed to send the ruleset reload request.'

            results.affected_items.append({'name': node_id, 'msg': result})
    except WazuhError as e:
        results.add_failed_item(id_=node_id, error=e)

    results.total_affected_items = len(results.affected_items)
    return results
