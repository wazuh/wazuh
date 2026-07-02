# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest.mock import MagicMock, patch

import pytest

with patch('wazuh.core.common.wazuh_uid'):
    with patch('wazuh.core.common.wazuh_gid'):
        sys.modules['wazuh.rbac.orm'] = MagicMock()
        import wazuh.rbac.decorators

        del sys.modules['wazuh.rbac.orm']

        from wazuh.tests.util import RBAC_bypasser

        wazuh.rbac.decorators.expose_resources = RBAC_bypasser
        from wazuh import cluster
        from wazuh.core import common
        from wazuh.core.exception import WazuhError, WazuhResourceNotFound
        from wazuh.core.cluster.local_client import LocalClient
        from wazuh.core.results import WazuhResult

default_config = {'disabled': True, 'node_type': 'master', 'name': 'wazuh', 'node_name': 'node01',
                  'key': '', 'port': 1516, 'bind_addr': '0.0.0.0', 'nodes': ['NODE_IP'], 'hidden': 'no'}


@patch('wazuh.rbac.decorators._has_update_permissions', return_value=True)
def test_read_config_wrapper(mock_perms):
    """Verify that the read_config_wrapper returns the default configuration."""
    fresh_config = dict(default_config)
    with patch('wazuh.cluster.read_config', return_value=fresh_config):
        result = cluster.read_config_wrapper()
    # Admin (has update perms) is not masked: the full config must be returned unchanged.
    assert result.affected_items[0] == default_config


@patch('wazuh.cluster.read_config', side_effect=WazuhError(1001))
def test_read_config_wrapper_exception(mock_read_config):
    """Verify the exceptions raised in read_config_wrapper."""
    result = cluster.read_config_wrapper()
    assert list(result.failed_items.keys())[0] == WazuhError(1001)


def _cluster_config_with_key():
    """Return a fresh cluster config dict carrying a real key.

    A new dict is built on every call so tests stay isolated even if a future
    change masks the affected item in place instead of a copy.
    """
    return {'disabled': False, 'node_type': 'master', 'name': 'wazuh', 'node_name': 'master-node',
            'key': 'REAL_CLUSTER_SECRET', 'port': 1516, 'bind_addr': '0.0.0.0',
            'nodes': ['wazuh-master'], 'hidden': 'no'}


@pytest.mark.parametrize('has_perms,expected_key', [
    (False, '*****'),
    (True, 'REAL_CLUSTER_SECRET'),
])
def test_read_config_wrapper_key_visibility(has_perms, expected_key):
    """Key is masked for readonly users and exposed for admins."""
    with patch('wazuh.rbac.decorators._has_update_permissions', return_value=has_perms):
        with patch('wazuh.cluster.read_config', return_value=_cluster_config_with_key()):
            result = cluster.read_config_wrapper()
    assert result.affected_items[0]['key'] == expected_key


@patch('wazuh.rbac.decorators._has_update_permissions', return_value=False)
def test_read_config_wrapper_masking_preserves_other_fields(mock_perms):
    """Masking only touches the key field, not other config fields."""
    with patch('wazuh.cluster.read_config', return_value=_cluster_config_with_key()):
        result = cluster.read_config_wrapper()
    item = result.affected_items[0]
    assert item['key'] == '*****'
    assert item['name'] == 'wazuh'
    assert item['node_name'] == 'master-node'
    assert item['port'] == 1516
    assert item['nodes'] == ['wazuh-master']


def test_read_config_wrapper_no_cache_poisoning():
    """Masking must not mutate the shared read_config() source dict (in-place-mutation regression guard)."""
    shared_config = _cluster_config_with_key()

    with patch('wazuh.cluster.read_config', return_value=shared_config):
        # Readonly: the response is masked, but the shared (cached) dict must stay intact
        with patch('wazuh.rbac.decorators._has_update_permissions', return_value=False):
            ro_result = cluster.read_config_wrapper()

        assert ro_result.affected_items[0]['key'] == '*****'
        assert shared_config['key'] == 'REAL_CLUSTER_SECRET'

        # A subsequent admin read still sees the real key (cache was not poisoned).
        with patch('wazuh.rbac.decorators._has_update_permissions', return_value=True):
            result = cluster.read_config_wrapper()

        assert result.affected_items[0]['key'] == 'REAL_CLUSTER_SECRET'


@patch('wazuh.cluster.read_config', return_value=default_config)
def test_node_wrapper(mock_read_config):
    """Verify that the node_wrapper returns the default node information."""
    result = cluster.get_node_wrapper()
    assert result.affected_items == [{'cluster': default_config["name"],
                                      'node': default_config["node_name"],
                                      'type': default_config["node_type"]}]


@patch('wazuh.cluster.get_node', side_effect=WazuhError(1001))
def test_node_wrapper_exception(mock_get_node):
    """Verify the exceptions raised in get_node_wrapper."""
    result = cluster.get_node_wrapper()
    assert list(result.failed_items.keys())[0] == WazuhError(1001)


def test_get_status_json():
    """Verify that get_status_json returns the default status information."""
    result = cluster.get_status_json()
    expected = WazuhResult({'data': {"enabled": "no" if default_config['disabled'] else "yes", "running": "no"}})
    assert result == expected


@pytest.mark.asyncio
@patch('wazuh.core.cluster.local_client.LocalClient.start', side_effect=None)
async def test_get_health_nodes(mock_unix_connection):
    """Verify that get_health_nodes returns the health of all nodes."""

    async def async_mock(lc=None, filter_node=None):
        return {'nodes': {'manager': {'info': {'name': 'master'}}}}

    local_client = LocalClient()
    with patch('wazuh.cluster.get_health', side_effect=async_mock):
        result = await cluster.get_health_nodes(lc=local_client)
    expected = await async_mock()

    assert result.affected_items == [expected['nodes']['manager']]


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


@pytest.mark.parametrize("ruleset_integrity", [
    True,
    False
])
@patch("wazuh.cluster.node_id", new="testing_node")
@pytest.mark.asyncio
async def test_get_ruleset_sync_status(ruleset_integrity):
    """Verify that `get_ruleset_sync_status` function correctly returns node ruleset synchronization status."""
    master_md5 = {'key1': 'value1'}
    with patch("wazuh.cluster.get_node_ruleset_integrity",
               return_value=master_md5 if ruleset_integrity else {}) as ruleset_integrity_mock:
        result = await cluster.get_ruleset_sync_status(master_md5=master_md5)
        assert result.total_affected_items == 1
        assert result.total_failed_items == 0
        assert result.affected_items[0]['name'] == "testing_node"
        assert result.affected_items[0]['synced'] is ruleset_integrity


@patch("wazuh.cluster.node_id", new="testing_node")
@pytest.mark.asyncio
async def test_get_ruleset_sync_status_ko():
    """Verify proper exceptions behavior with `get_ruleset_sync_status`."""
    exc = WazuhError(1000)
    with patch("wazuh.cluster.get_node_ruleset_integrity", side_effect=exc):
        result = await cluster.get_ruleset_sync_status(master_md5={})
        assert result.total_affected_items == 0
        assert result.total_failed_items == 1
        assert result.failed_items[exc] == {"testing_node"}
