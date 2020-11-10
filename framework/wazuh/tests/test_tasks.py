#!/usr/bin/env python
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import patch, MagicMock

import pytest

from wazuh.tests.util import InitWDBSocketMock

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        sys.modules['api'] = MagicMock()
        import wazuh.rbac.decorators
        del sys.modules['wazuh.rbac.orm']
        del sys.modules['api']

        from wazuh.tests.util import RBAC_bypasser
        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh import syscollector
        from wazuh import tasks
        from wazuh.core.results import AffectedItemsWazuhResult


# Tests

@pytest.mark.parametrize("task_list, tasks_return_value, affected", [
    ([1, 2, 3],
     {'data': [{'error': 0, 'message': 'Success', 'agent': 1, 'task_id': 1, 'node': 'worker1',
                'module': 'upgrade_module',
       'command': 'upgrade', 'status': 'Legacy', 'create_time': '2020/10/22 12:24:08',
       'update_time': '2020/10/22 12:24:21'},
      {'error': 0, 'message': 'Success', 'agent': 2, 'task_id': 2, 'node': 'worker2', 'module': 'upgrade_module',
       'command': 'upgrade', 'status': 'Legacy', 'create_time': '2020/10/22 12:24:12',
       'update_time': '2020/10/22 12:24:27'},
      {'error': 0, 'message': 'Success', 'agent': 3, 'task_id': 3, 'node': 'worker2', 'module': 'upgrade_module',
       'command': 'upgrade', 'status': 'Legacy', 'create_time': '2020/10/22 12:24:12',
       'update_time': '2020/10/22 12:24:27'}]}, True),
    ([4], {'data': [{'error': 8, 'message': 'No task in DB', 'task_id': 4}]}, False)
])
def test_get_item_agent(task_list, tasks_return_value, affected):
    """Check system's tasks

    Parameters
    ----------
    task_list : list
        List of task ids
    """
    with patch("wazuh.tasks.send_to_tasks_socket") as send_to_tasks:
        send_to_tasks.return_value = tasks_return_value
        result = tasks.get_task_status(task_list=task_list)

    assert result.total_affected_items if affected else result.total_failed_items == len(tasks_return_value['data'])
