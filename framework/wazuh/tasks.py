# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from typing import Dict

from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.utils import read_cluster_config
from wazuh.core.common import database_limit
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.tasks import WazuhDBQueryTasks
from wazuh.core.utils import sort_array
from wazuh.rbac.decorators import expose_resources

logger = logging.getLogger('wazuh')

cluster_enabled = not read_cluster_config()['disabled']
node_id = get_node().get('node') if cluster_enabled else None


@expose_resources(actions=["tasks:status"], resources=["*:*:*"], post_proc_kwargs={'exclude_codes': [1817]})
def get_task_status(task_list=None, agent_id: str = None, command: str = None, node: str = None, module: str = None,
                    status: str = None, select: list = None, search: dict = None, offset: int = 0,
                    limit: int = database_limit, sort: dict = None, q: str = None, ) -> Dict:
    """Read the status of the specified task IDs

    Parameters
    ----------
    task_list : list
        List of task ID's.
    agent_id : str
        Specified agent id
    command : str
        Command executed in the task
    node : str
        Node where task is executed
    module : str
        Module responsible for task
    status : str
        Task's status
    select : dict
        Select fields to return. Format: {"fields":["field1","field2"]}
    search : str
        Search if the string is contained in the db
    offset : int
        First item to return
    limit : int
        Maximum number of items to return
    sort : dict
        Sort the items. Format: {'fields': ['field1', 'field2'], 'order': 'asc|desc'}
    q : str
        Query to filter by

    Returns
    -------
    Tasks's status.
    """
    result = AffectedItemsWazuhResult(all_msg='All specified task\'s status were returned',
                                      some_msg='Some status were not returned',
                                      none_msg='No status was returned')

    if agent_id:
        q = f'{q};agent_id={int(agent_id)}' if q else f'agent_id={int(agent_id)}'
    if module:
        q = f'{q};module={module}' if q else f'module={module}'
    if status:
        q = f'{q};status={status}' if q else f'status={status}'
    if node:
        q = f'{q};node={node}' if q else f'node={node}'
    if command:
        q = f'{q};command={command}' if q else f'command={command}'

    db_query = WazuhDBQueryTasks(filters={'task_id': task_list} if task_list else None, offset=offset,
                                 limit=limit, query=q, sort=sort, search=search, select=select)
    data = db_query.run()

    # Sort result array
    if sort and 'json' not in sort['fields']:
        data['items'] = sort_array(data['items'], sort_by=sort['fields'], sort_ascending=sort['order'] == 'asc')

    result.affected_items.extend(data['items'])
    result.total_affected_items = data['totalItems']

    return result
