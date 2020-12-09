# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging
from typing import Dict

from wazuh.core.cluster.cluster import get_node
from wazuh.core.cluster.utils import read_cluster_config
from wazuh.core.common import database_limit
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.task import WazuhDBQueryTask
from wazuh.core.utils import sort_array
from wazuh.rbac.decorators import expose_resources

logger = logging.getLogger('wazuh')

cluster_enabled = not read_cluster_config()['disabled']
node_id = get_node().get('node') if cluster_enabled else None


@expose_resources(actions=["task:status"], resources=["*:*:*"], post_proc_kwargs={'exclude_codes': [1817]})
def get_task_status(filters: dict = None, select: list = None, search: dict = None, offset: int = 0,
                    limit: int = database_limit, sort: dict = None, q: str = None, ) -> Dict:
    """Read the status of the specified task IDs

    Parameters
    ----------
    filters : dict
        Defines required field filters. Format: {"field1":"value1", "field2":["value2","value3"]}
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

    db_query = WazuhDBQueryTask(filters=filters, offset=offset, limit=limit, query=q, sort=sort, search=search,
                                 select=select)
    data = db_query.run()

    # Sort result array
    if sort and 'json' not in sort['fields']:
        data['items'] = sort_array(data['items'], sort_by=sort['fields'], sort_ascending=sort['order'] == 'asc')

    # Add zeros to agent IDs
    for element in data['items']:
        element['agent_id'] = str(element['agent_id']).zfill(3)

    result.affected_items.extend(data['items'])
    result.total_affected_items = data['totalItems']

    return result
