# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from wazuh.core.tasks import send_to_tasks_socket
from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.utils import read_cluster_config
from wazuh.core.exception import WazuhError
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.rbac.decorators import expose_resources

logger = logging.getLogger('wazuh')

cluster_enabled = not read_cluster_config()['disabled']
node_id = get_node().get('node') if cluster_enabled else None


@expose_resources(actions=["tasks:status"], resources=["*:*:*"], post_proc_kwargs={'exclude_codes': [1817]})
def get_task_status(task_list=None):
    """Read the status of the specified task IDs

    Parameters
    ----------
    task_list : list
        List of task ID's.

    Returns
    -------
    Tasks's status.
    """
    result = AffectedItemsWazuhResult(all_msg='All specified task\'s status were returned',
                                      some_msg='Some status were not returned',
                                      none_msg='No status was returned')

    command_list = list()
    if task_list:
        for task in task_list:
            command_list.append({'command': 'task_result', 'module': 'api', 'task_id': int(task)})

    task_results = send_to_tasks_socket(command_list)
    if not isinstance(task_results, list):
        task_results['data'] = 'Invalid task ID'
        task_results = [task_results]
    for task_result in task_results:
        task_error = task_result.pop('error')
        if task_error == 0:
            result.affected_items.append(task_result)
            result.total_affected_items += 1
        else:
            error = WazuhError(code=1850 + task_error, cmd_error=True, extra_message=task_result['data'])
            result.add_failed_item(id_=str(task_result.pop('task_id', None)), error=error)

    result.affected_items = sorted(result.affected_items, key=lambda k: k['task_id'])

    return result
