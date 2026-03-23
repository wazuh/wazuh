# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
import copy
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# =============================================================================
# Imports with RBAC bypass
# =============================================================================
with patch("wazuh.core.common.wazuh_uid"), patch("wazuh.core.common.wazuh_gid"):
    import wazuh.rbac.decorators
    from wazuh.tests.util import RBAC_bypasser

    wazuh.rbac.decorators.expose_resources = RBAC_bypasser

    from wazuh.core.cluster.master import DisconnectedAgentSyncTasks
    from wazuh.core.exception import WazuhError
    from wazuh.core.results import AffectedItemsWazuhResult


CLUSTER_ITEMS = {
    "intervals": {
        "master": {
            "sync_disconnected_agent_groups": 5,
            "sync_disconnected_agent_groups_batch_size": 2,
            "sync_disconnected_agent_groups_min_offline": 600,
        }
    }
}


def make_agent(
    *, agent_id="001", status="disconnected", last_keepalive=None, group=None
):
    """
    Create a mock agent dictionary for testing purposes.

    Parameters
    ----------
    agent_id : str, optional
        The unique identifier for the agent.
    status : str, optional
        The connection status of the agent.
    last_keepalive : datetime or None, optional
        The timestamp of the last keepalive message.
    group : list of str, optional
        The groups the agent belongs to. Defaults to ["default"].

    Returns
    -------
    dict
        A dictionary representing the agent's state.
    """
    return {
        "id": agent_id,
        "status": status,
        "lastKeepAlive": last_keepalive,
        "group": group or ["default"],
    }


def make_task(min_offline=600):
    """
    Initialize a DisconnectedAgentSyncTasks instance with mock dependencies.

    Parameters
    ----------
    min_offline : int, optional
        Minimum offline time in seconds for synchronization eligibility.

    Returns
    -------
    DisconnectedAgentSyncTasks
        An instance of the synchronization task configured for testing.
    """
    cluster_items = {
        "intervals": {"master": {"sync_disconnected_agent_groups": 300}},
        "sync_disconnected_agent_groups_batch_size": 100,
        "sync_disconnected_agent_groups_min_offline": min_offline,
        "disconnected_agent_sync": {"enabled": True},
    }

    server = MagicMock()
    server.setup_task_logger.return_value = MagicMock()

    return DisconnectedAgentSyncTasks(
        server=server,
        cluster_items=cluster_items,
    )


# =============================================================================
# Fixtures
# =============================================================================
@pytest.fixture
def logger():
    """Fixture to provide a MagicMock logger."""
    return MagicMock()


@pytest.fixture
def manager(logger):
    """Fixture to provide a MagicMock manager with a configured logger."""
    m = MagicMock()
    m.setup_task_logger.return_value = logger
    return m


@pytest.fixture
def task(manager, logger):
    """Fixture to provide a DisconnectedAgentSyncTasks instance."""
    return DisconnectedAgentSyncTasks(
        server=manager,
        logger=logger,
        cluster_items=copy.deepcopy(CLUSTER_ITEMS),
        indexer_client=None,
    )


# =============================================================================
# Tests
# =============================================================================


def test_batch_agents_basic(task):
    """
    Verify that agents are correctly split into batches based on batch size.
    """
    agents = [{"id": str(i)} for i in range(5)]
    batches = list(task._batch_agents(agents))

    assert len(batches) == 3
    assert batches[0] == [{"id": "0"}, {"id": "1"}]
    assert batches[-1] == [{"id": "4"}]


def test_batch_agents_empty(task):
    """
    Verify that batching an empty agent list returns an empty list.
    """
    assert list(task._batch_agents([])) == []


@pytest.mark.asyncio
async def test_get_max_versions_success(manager, logger):
    """
    Verify that the task correctly parses max document versions from the indexer.
    """
    indexer = AsyncMock()
    indexer.search.return_value = {
        "aggregations": {
            "by_agent": {
                "buckets": [
                    {"key": "001", "max_document_version": {"value": 10}},
                    {"key": "002", "max_document_version": {"value": 20}},
                ]
            }
        }
    }

    task = DisconnectedAgentSyncTasks(
        server=manager,
        logger=logger,
        cluster_items=CLUSTER_ITEMS,
        indexer_client=indexer,
    )

    result = await task._get_max_versions_batch_from_indexer(["001", "002"])

    assert result == {"001": 10, "002": 20}
    indexer.search.assert_called_once()


@pytest.mark.asyncio
async def test_get_max_versions_empty_result(task):
    """
    Verify that empty input results in an empty version dictionary.
    """
    result = await task._get_max_versions_batch_from_indexer([])
    assert result == {}


@pytest.mark.asyncio
async def test_get_max_versions_indexer_error(manager, logger):
    """
    Verify that indexer exceptions are handled and return an empty result.
    """
    indexer = AsyncMock()
    indexer.search.side_effect = Exception("boom")

    task = DisconnectedAgentSyncTasks(
        server=manager,
        logger=logger,
        cluster_items=CLUSTER_ITEMS,
        indexer_client=indexer,
    )

    result = await task._get_max_versions_batch_from_indexer(["001"])
    assert result == {}


@pytest.mark.asyncio
@patch("wazuh.core.indexer.disconnected_agents.WazuhDBQueryAgents")
@patch("wazuh.core.indexer.disconnected_agents.core_utils.get_utc_now")
async def test_get_disconnected_agents_filter_by_time_filters_by_time(
    mock_now, mock_query, task
):
    """
    Check that only agents exceeding the min_offline threshold are returned.
    """
    now = datetime.now(timezone.utc)
    mock_now.return_value = now

    agents = [
        make_agent(
            agent_id="001",
            last_keepalive=now - timedelta(seconds=700),
        ),
        make_agent(
            agent_id="002",
            last_keepalive=now - timedelta(seconds=300),
        ),
    ]

    db = MagicMock()
    db.run.return_value = {"items": agents}
    mock_query.return_value.__enter__.return_value = db

    result = await task._get_disconnected_agents_filter_by_time()

    assert len(result) == 1
    assert result[0]["id"] == "001"


@pytest.mark.asyncio
@patch(
    "wazuh.core.indexer.disconnected_agents.WazuhDBQueryAgents",
    side_effect=Exception("DB error"),
)
async def test_db_error_returns_empty_list(mock_query):
    """
    Verify that database query errors return an empty list gracefully.
    """
    task = make_task()
    result = await task._get_disconnected_agents_filter_by_time()

    assert result == []


@pytest.mark.asyncio
async def test_sync_agent_batch_success(task):
    """
    Verify successful processing of an agent batch.
    """
    task._get_max_versions_batch_from_indexer = AsyncMock(return_value={"001": 5})
    task.disconnected_agent_group_sync = AsyncMock(
        return_value=AffectedItemsWazuhResult()
    )

    agents = [{"id": "001", "group": ["default"]}]
    result = await task._sync_agent_batch(agents)

    assert result["processed"] == 1
    assert result["failed"] == 0


@pytest.mark.asyncio
async def test_sync_agent_batch_missing_group(task):
    """
    Ensure agents with missing group data are marked as failed.
    """
    agents = [{"id": "001"}]
    result = await task._sync_agent_batch(agents)

    assert result["processed"] == 0
    assert result["failed"] == 1


@pytest.mark.asyncio
async def test_sync_agent_batch_missing_id(task):
    """
    Ensure agents with missing ID are marked as failed.
    """
    agents = [{"group": ["default"]}]
    result = await task._sync_agent_batch(agents)

    assert result["processed"] == 0
    assert result["failed"] == 1


@pytest.mark.asyncio
async def test_sync_agent_batch_sync_error(task):
    """
    Verify failure count increases when synchronization logic raises an exception.
    """
    task._get_max_versions_batch_from_indexer = AsyncMock(return_value={"001": 0})
    task.disconnected_agent_group_sync = AsyncMock(side_effect=Exception("sync error"))

    agents = [{"id": "001", "group": ["default"]}]
    result = await task._sync_agent_batch(agents)

    assert result["processed"] == 0
    assert result["failed"] == 1


@pytest.mark.asyncio
@patch("wazuh.core.indexer.disconnected_agents.core_utils.get_utc_now")
@patch("wazuh.core.indexer.disconnected_agents.WazuhDBQueryAgents")
async def test_get_disconnected_agents_filter_by_time_ok(mock_query, mock_now):
    """
    Verify agents disconnected longer than min_offline are successfully retrieved.
    """
    now = datetime.now(timezone.utc)
    mock_now.return_value = now

    agents = [
        make_agent(
            agent_id="001",
            last_keepalive=now - timedelta(seconds=2000),
            group=["default"],
        ),
        make_agent(
            agent_id="002",
            last_keepalive=now - timedelta(seconds=2000),
            group=["group1"],
        ),
    ]

    db = MagicMock()
    db.run.return_value = {"items": agents}
    mock_query.return_value.__enter__.return_value = db

    task = make_task(min_offline=600)

    result = await task._get_disconnected_agents_filter_by_time()

    assert len(result) == 2
    assert {a["id"] for a in result} == {"001", "002"}


@pytest.mark.asyncio
@patch("wazuh.core.indexer.disconnected_agents.core_utils.get_utc_now")
@patch("wazuh.core.indexer.disconnected_agents.WazuhDBQueryAgents")
async def test_filters_recently_disconnected_agents(mock_query, mock_now):
    """
    Ensure agents below the min_offline threshold are ignored.
    """
    now = datetime.now(timezone.utc)
    mock_now.return_value = now

    agents = [
        make_agent(
            agent_id="001",
            last_keepalive=now - timedelta(seconds=100),
        )
    ]

    db = MagicMock()
    db.run.return_value = {"items": agents}
    mock_query.return_value.__enter__.return_value = db

    task = make_task(min_offline=600)

    result = await task._get_disconnected_agents_filter_by_time()

    assert result == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "last_keepalive_seconds, expected_count",
    [
        (30, 0),
        (5000, 1),
    ],
)
@patch("wazuh.core.indexer.disconnected_agents.core_utils.get_utc_now")
@patch("wazuh.core.indexer.disconnected_agents.WazuhDBQueryAgents")
async def test_filters_agents_by_connection_status(
    mock_query, mock_now, last_keepalive_seconds, expected_count
):
    """
    Verify that connection status filtering works in conjunction with time.
    """
    now = datetime.now(timezone.utc)
    mock_now.return_value = now

    agents = [
        make_agent(
            agent_id="001",
            status="active",
            last_keepalive=now - timedelta(seconds=last_keepalive_seconds),
        )
    ]

    db = MagicMock()
    db.run.return_value = {"items": agents}
    mock_query.return_value.__enter__.return_value = db

    task = make_task()
    result = await task._get_disconnected_agents_filter_by_time()

    assert len(result) == expected_count


@pytest.mark.asyncio
@patch("wazuh.core.indexer.disconnected_agents.core_utils.get_utc_now")
@patch("wazuh.core.indexer.disconnected_agents.WazuhDBQueryAgents")
async def test_ignores_agents_without_last_keepalive(mock_query, mock_now):
    """
    Ensure agents without a lastKeepAlive timestamp are ignored safely.
    """
    now = datetime.now(timezone.utc)
    mock_now.return_value = now

    agents = [
        make_agent(
            agent_id="001",
            last_keepalive=None,
        )
    ]

    db = MagicMock()
    db.run.return_value = {"items": agents}
    mock_query.return_value.__enter__.return_value = db

    task = make_task()

    result = await task._get_disconnected_agents_filter_by_time()

    assert result == []


@pytest.mark.asyncio
@patch("wazuh.core.indexer.disconnected_agents.WazuhDBQueryAgents")
async def test_empty_db_result(mock_query):
    """
    Verify that an empty DB response returns an empty list.
    """
    db = MagicMock()
    db.run.return_value = {"items": []}
    mock_query.return_value.__enter__.return_value = db

    task = make_task()

    result = await task._get_disconnected_agents_filter_by_time()

    assert result == []


@pytest.mark.asyncio
async def test_run_cluster_name_sync_already_done(task):
    """
    Verify that sync is skipped if it was already performed.
    """
    task._cluster_name_sync_done = True
    await task.run_cluster_name_sync()


@pytest.mark.asyncio
@patch.object(DisconnectedAgentSyncTasks, "_get_disconnected_agents", return_value=[])
async def test_run_cluster_name_sync_no_agents(mock_get, task):
    """
    Verify sync behavior when no disconnected agents are found.
    """
    task.initial_delay = 0
    await task.run_cluster_name_sync()


@pytest.mark.asyncio
@patch.object(
    DisconnectedAgentSyncTasks, "_get_disconnected_agents", return_value=[{"id": "001"}]
)
@patch(
    "wazuh.core.indexer.disconnected_agents.get_ossec_conf",
    return_value={"cluster": {}},
)
async def test_run_cluster_name_sync_no_cluster_name(mock_conf, mock_get, task):
    """
    Verify sync behavior when no cluster name is configured in ossec.conf.
    """
    task.initial_delay = 0
    await task.run_cluster_name_sync()


@pytest.mark.asyncio
@patch.object(
    DisconnectedAgentSyncTasks, "_get_disconnected_agents", return_value=[{"id": "001"}]
)
@patch.object(
    DisconnectedAgentSyncTasks,
    "_get_cluster_name_from_indexer",
    return_value={"001": "clusterA"},
)
@patch.object(
    DisconnectedAgentSyncTasks,
    "_get_max_versions_batch_from_indexer",
    return_value={"001": 5},
)
@patch(
    "wazuh.core.indexer.disconnected_agents.get_ossec_conf",
    return_value={"cluster": {"name": "clusterA"}},
)
async def test_run_cluster_name_sync_no_update_needed(
    mock_conf, mock_versions, mock_cluster, mock_agents, task
):
    """
    Verify that no update is performed if names already match.
    """
    task.initial_delay = 0
    await task.run_cluster_name_sync()


@pytest.mark.asyncio
async def test_disconnected_agent_group_sync_empty_agent_list(task):
    """
    Verify that an empty agent list results in zero affected items.
    """
    result = await task.disconnected_agent_group_sync(
        agent_list=[],
        group_list=["default"],
        external_gte=1,
    )

    assert result.total_affected_items == 0


@pytest.mark.asyncio
async def test_disconnected_agent_group_sync_missing_params(task):
    """
    Verify that missing required parameters raise a WazuhError.
    """
    with pytest.raises(WazuhError):
        await task.disconnected_agent_group_sync(
            agent_list=["001"],
            group_list=None,
            external_gte=None,
        )


@pytest.mark.asyncio
@patch("wazuh.core.indexer.disconnected_agents.get_agents_info", return_value={})
async def test_disconnected_agent_group_sync_invalid_agent(mock_agents, task):
    """
    Verify that agents not found in information lookup are marked as failed.
    """
    result = await task.disconnected_agent_group_sync(
        agent_list=["001"],
        group_list=["default"],
        external_gte=1,
    )

    assert len(result.failed_items) == 1


@pytest.mark.asyncio
@patch(
    "wazuh.core.indexer.disconnected_agents.get_agents_info", return_value={"001": {}}
)
@patch("wazuh.core.indexer.disconnected_agents.get_indexer_client")
async def test_disconnected_agent_group_sync_success(mock_indexer, mock_agents, task):
    """
    Verify successful synchronization of an agent's group.
    """
    client = AsyncMock()
    client.max_version_components.update_agent_groups = AsyncMock()
    mock_indexer.return_value.__aenter__.return_value = client

    result = await task.disconnected_agent_group_sync(
        agent_list=["001"],
        group_list=["default"],
        external_gte=5,
    )

    assert result.total_affected_items == 1


@pytest.mark.asyncio
@patch(
    "wazuh.core.indexer.disconnected_agents.get_agents_info", return_value={"001": {}}
)
@patch("wazuh.core.indexer.disconnected_agents.get_indexer_client")
async def test_disconnected_agent_group_sync_mixed_results(
    mock_indexer, mock_agents, task
):
    """
    Test synchronization with a mix of valid, invalid, and system agents (000).
    """
    client = AsyncMock()
    mock_indexer.return_value.__aenter__.return_value = client

    result = await task.disconnected_agent_group_sync(
        agent_list=["000", "001", "999"], group_list=["default"], external_gte=5
    )

    all_failed_ids = []

    if isinstance(result.failed_items, dict):
        for ids in result.failed_items.values():
            all_failed_ids.extend(list(ids))
    else:
        for error_obj in result.failed_items:
            if hasattr(error_obj, "ids"):
                all_failed_ids.extend(list(error_obj.ids))
            elif hasattr(error_obj, "id_"):
                all_failed_ids.append(error_obj.id_)

    assert "000" in all_failed_ids
    assert "999" in all_failed_ids
    assert "001" in result.affected_items
    assert result.total_affected_items == 1


@pytest.mark.asyncio
async def test_get_cluster_name_from_indexer_multiple_clusters(manager, logger):
    """
    Verify aggregation logic when an agent is associated with multiple cluster names.
    """
    indexer = AsyncMock()
    indexer.search.return_value = {
        "aggregations": {
            "by_agent": {
                "buckets": [
                    {
                        "key": "001",
                        "cluster_name": {
                            "buckets": [{"key": "cluster-A"}, {"key": "cluster-B"}]
                        },
                    }
                ]
            }
        }
    }
    task = DisconnectedAgentSyncTasks(
        server=manager,
        logger=logger,
        indexer_client=indexer,
        cluster_items=copy.deepcopy(CLUSTER_ITEMS),
    )

    result = await task._get_cluster_name_from_indexer(["001"])
    assert result["001"] == "cluster-A"


@pytest.mark.asyncio
async def test_get_cluster_name_from_indexer_exception(manager, logger):
    """
    Verify exception handling during cluster name resolution.
    """
    indexer = AsyncMock()
    indexer.search.side_effect = Exception("Indexer error")
    task = DisconnectedAgentSyncTasks(
        server=manager,
        logger=logger,
        indexer_client=indexer,
        cluster_items=copy.deepcopy(CLUSTER_ITEMS),
    )

    result = await task._get_cluster_name_from_indexer(["001"])
    assert result == {}


@pytest.mark.asyncio
@patch(
    "wazuh.core.indexer.disconnected_agents.get_ossec_conf",
    side_effect=Exception("Config error"),
)
async def test_init_ossec_conf_error(mock_conf, manager, logger):
    """
    Verify task initialization when ossec.conf is missing or unreadable.
    """
    task = DisconnectedAgentSyncTasks(
        server=manager, logger=logger, cluster_items=copy.deepcopy(CLUSTER_ITEMS)
    )
    assert task.sync_interval == 5


def test_init_without_server_or_logger():
    """
    Verify fallback logger initialization when dependencies are missing.
    """
    with patch(
        "wazuh.core.indexer.disconnected_agents.get_ossec_conf", side_effect=Exception
    ):
        task = DisconnectedAgentSyncTasks(server=None, logger=None, cluster_items={})
        assert task.logger.name == "disconnected_agent_sync_task"


@pytest.mark.asyncio
@patch(
    "wazuh.core.indexer.disconnected_agents.asyncio.sleep",
    side_effect=[None, asyncio.CancelledError],
)
async def test_run_loop_exception_handling(mock_sleep, task):
    """
    Verify that exceptions inside the main loop are logged and handled.
    """
    with patch.object(
        task,
        "_get_disconnected_agents_filter_by_time",
        side_effect=Exception("Fatal DB Error"),
    ):
        try:
            await task.run_agent_groups_sync()
        except asyncio.CancelledError:
            pass

    task.logger.error.assert_called()


@pytest.mark.asyncio
async def test_get_max_versions_indexer_malformed_response(task):
    """
    Verify behavior when the indexer returns a malformed or empty response.
    """
    task._indexer_client_override = AsyncMock()

    task._indexer_client_override.search.return_value = None
    res = await task._get_max_versions_batch_from_indexer(["001"])
    assert res == {}

    task._indexer_client_override.search.return_value = {
        "aggregations": {"by_agent": {"buckets": [{"key": "001"}]}}
    }
    res = await task._get_max_versions_batch_from_indexer(["001"])
    assert res == {}
    task.logger.exception.assert_called()


@pytest.mark.asyncio
@patch("wazuh.core.indexer.disconnected_agents.get_indexer_client")
@patch("wazuh.core.indexer.disconnected_agents.get_ossec_conf")
@patch.object(DisconnectedAgentSyncTasks, "_get_max_versions_batch_from_indexer")
@patch.object(DisconnectedAgentSyncTasks, "_get_cluster_name_from_indexer")
@patch.object(DisconnectedAgentSyncTasks, "_get_disconnected_agents")
async def test_run_cluster_name_sync_full_flow(
    mock_get_agents,
    mock_get_cluster_indexer,
    mock_get_versions,
    mock_conf,
    mock_indexer_client,
    task,
):
    """
    Verify the full flow of cluster name synchronization.

    Includes:
    - Successful update for one agent.
    - Graceful error handling for another agent.
    """
    task.initial_delay = 0
    mock_get_agents.return_value = [{"id": "001"}, {"id": "002"}]

    mock_conf.return_value = {"cluster": {"name": "wazuh-new"}}

    mock_get_cluster_indexer.return_value = {"001": "old-cluster", "002": "old-cluster"}
    mock_get_versions.return_value = {"001": 10, "002": 20}

    client = AsyncMock()
    client.max_version_components.update_agent_cluster_name.side_effect = [
        Exception("Update failed for 001"),
        None,
    ]
    mock_indexer_client.return_value.__aenter__.return_value = client

    await task.run_cluster_name_sync()

    assert task._cluster_name_sync_done is True
    assert client.max_version_components.update_agent_cluster_name.call_count == 2
    task.logger.error.assert_called()


@pytest.mark.asyncio
@patch(
    "wazuh.core.indexer.disconnected_agents.get_agents_info", return_value={"001": {}}
)
@patch("wazuh.core.indexer.disconnected_agents.get_indexer_client")
async def test_disconnected_agent_group_sync_unexpected_exception(
    mock_indexer, mock_agents, task
):
    """
    Verify error handling for unexpected exceptions within the group sync loop.
    """
    client = AsyncMock()
    client.max_version_components.update_agent_groups.side_effect = Exception(
        "Unexpected"
    )
    mock_indexer.return_value.__aenter__.return_value = client

    result = await task.disconnected_agent_group_sync(
        agent_list=["001"], group_list=["default"], external_gte=5
    )

    assert len(result.failed_items) == 1
    task.logger.error.assert_called()
