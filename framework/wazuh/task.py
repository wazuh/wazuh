# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import logging

from wazuh.core.common import DATABASE_LIMIT
from wazuh.core.results import AffectedItemsWazuhResult
from wazuh.core.task import WazuhDBQueryTask
from wazuh.rbac.decorators import expose_resources

logger = logging.getLogger('wazuh')


@expose_resources(actions=["task:status"], resources=["*:*:*"], post_proc_kwargs={'exclude_codes': [1817]})
def get_task_status(filters: dict = None, select: list = None, search: dict = None, offset: int = 0,
                    limit: int = DATABASE_LIMIT, sort: dict = None, q: str = None, ) -> AffectedItemsWazuhResult:
    """Read the status of the specified task IDs.

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
    AffectedItemsWazuhResult
        Tasks's status.
    """
    result = AffectedItemsWazuhResult(all_msg='All specified task\'s status were returned',
                                      some_msg='Some status were not returned',
                                      none_msg='No status was returned')

    with WazuhDBQueryTask(filters=filters, offset=offset, limit=limit, query=q, sort=sort, search=search,
                          select=select) as db_query:
        data = db_query.run()

    # Fill with zeros the agent_id
    for element in data['items']:
        try:
            element['agent_id'] = str(element['agent_id']).zfill(3)
        except KeyError:
            pass

    result.affected_items.extend(data['items'])
    result.total_affected_items = data['totalItems']

    return result
