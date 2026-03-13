import sys
from unittest.mock import MagicMock, patch

import pytest

mocked_modules = {
    "wazuh.core.agent": MagicMock(),
    "wazuh.core.common": MagicMock(),
    "wazuh.core.configuration": MagicMock(),
    "wazuh.core.stats": MagicMock(),
    "wazuh.core.utils": MagicMock(),
    "wazuh.core.InputValidator": MagicMock(),
    "wazuh.core.cluster": MagicMock(),
    "wazuh.core.cluster.utils": MagicMock(),
    "wazuh.core.exception": MagicMock(),
    "wazuh.core.wazuh_queue": MagicMock(),
    "wazuh.core.wazuh_socket": MagicMock(),
    "wazuh.core.wdb": MagicMock(),
    "wazuh.core.wdb_http": MagicMock(),
    "wazuh.rbac": MagicMock(),
    "wazuh.rbac.utils": MagicMock(),
}

with patch.dict(sys.modules, mocked_modules):
    from wazuh.core.indexer.metrics_snapshot import MetricsSnapshotTasks


@pytest.mark.asyncio
@patch("wazuh.core.indexer.metrics_snapshot.WazuhDBQueryAgents")
async def test_collect_agents(mock_wazuh_db_query_agents):
    mock_server = MagicMock()
    mock_server.configuration.get.side_effect = lambda k, d: (
        "test_node" if k == "node_name" else "worker"
    )

    mock_query_instance = MagicMock()
    mock_query_instance.run.return_value = {
        "items": [
            {"id": "001", "name": "ubuntu-agent"},
            {"id": "002", "name": "windows-agent"},
        ]
    }
    mock_wazuh_db_query_agents.return_value = mock_query_instance

    cluster_items = {
        "intervals": {"master": {"metrics_frequency": 600, "metrics_bulk_size": 100}}
    }

    task = MetricsSnapshotTasks(server=mock_server, cluster_items=cluster_items)
    TEST_TIMESTAMP = "2026-03-13T10:00:00Z"

    result = await task._collect_agents(TEST_TIMESTAMP)

    mock_wazuh_db_query_agents.assert_called_once_with(limit=None)

    assert len(result) == 2
    for agent_doc in result:
        assert agent_doc["@timestamp"] == TEST_TIMESTAMP
        assert agent_doc["wazuh.cluster.node_name"] == "test_node"
        assert agent_doc["wazuh.cluster.node_type"] == "worker"
        assert "id" in agent_doc
        assert "name" in agent_doc
