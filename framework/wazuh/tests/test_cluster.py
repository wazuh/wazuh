# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch

import pytest
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.config.models.base import ValidateFilePathMixin
from wazuh.tests.util import get_default_configuration

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        with patch.object(ValidateFilePathMixin, '_validate_file_path', return_value=None):
            default_config = get_default_configuration()
            CentralizedConfig._config = default_config

            import wazuh.rbac.decorators
            from wazuh.tests.util import RBAC_bypasser

            wazuh.rbac.decorators.expose_resources = RBAC_bypasser
            from wazuh import cluster
            from wazuh.core import common
            from wazuh.core.cluster.local_client import LocalClient
            from wazuh.core.exception import WazuhError, WazuhResourceNotFound


async def test_node_wrapper():
    """Verify that the node_wrapper returns the default node information."""
    result = await cluster.get_node_wrapper()
    assert result.affected_items == [{'node': default_config.server.node.name, 'type': default_config.server.node.type}]


@patch('wazuh.cluster.get_node', side_effect=WazuhError(1001))
async def test_node_wrapper_exception(mock_get_node):
    """Verify the exceptions raised in get_node_wrapper."""
    result = await cluster.get_node_wrapper()
    assert list(result.failed_items.keys())[0] == WazuhError(1001)


@pytest.mark.asyncio
async def test_get_nodes_info():
    """Verify that get_nodes_info returns the information of all nodes."""

    async def valid_node(lc=None, filter_node=None):
        return {'items': ['master', 'worker1'], 'totalItems': 2}

    local_client = LocalClient()
    common.cluster_nodes.set(['master', 'worker1', 'worker2'])
    with patch('wazuh.cluster.get_nodes', side_effect=valid_node):
        result = await cluster.get_nodes_info(lc=local_client, filter_node=['master', 'worker1', 'noexists'])
    expected = await valid_node()

    assert result.affected_items == expected['items']
    assert result.total_affected_items == expected['totalItems']
    assert result.failed_items[WazuhResourceNotFound(1730)] == {'noexists'}
    assert result.total_failed_items == 1
