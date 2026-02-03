# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import copy
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# =============================
# Imports con RBAC bypass
# =============================
with patch("wazuh.core.common.wazuh_uid"), patch("wazuh.core.common.wazuh_gid"):
    import wazuh.rbac.decorators
    from wazuh.tests.util import RBAC_bypasser

    wazuh.rbac.decorators.expose_resources = RBAC_bypasser

    from wazuh.core.cluster.master import DisconnectedAgentSyncTasks
    from wazuh.core.results import AffectedItemsWazuhResult


# =============================
# Cluster config base
# =============================
CLUSTER_ITEMS = {
    "intervals": {
        "master": {
            "sync_disconnected_agent_groups": 5,
            "sync_disconnected_agent_groups_batch_size": 2,
            "sync_disconnected_agent_groups_min_offline": 600,
        }
    }
}


# =========================
# Helpers
# =========================


def make_agent(
    *,
    agent_id="001",
    status="disconnected",
    last_keepalive=None,
    group=None,
):
    return {
        "id": agent_id,
        "status": status,
        "lastKeepAlive": last_keepalive,
        "group": group or ["default"],
    }


def make_task(min_offline=600):
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


# =============================
# Fixtures
# =============================
@pytest.fixture
def logger():
    return MagicMock()


@pytest.fixture
def manager(logger):
    m = MagicMock()
    m.setup_task_logger.return_value = logger
    return m


@pytest.fixture
def task(manager, logger):
    return DisconnectedAgentSyncTasks(
        server=manager,
        logger=logger,
        cluster_items=copy.deepcopy(CLUSTER_ITEMS),
        indexer_client=None,
    )


# ============================================================
# _batch_agents
# ============================================================
def test_batch_agents_basic(task):
    agents = [{"id": str(i)} for i in range(5)]
    batches = list(task._batch_agents(agents))

    assert len(batches) == 3
    assert batches[0] == [{"id": "0"}, {"id": "1"}]
    assert batches[-1] == [{"id": "4"}]


def test_batch_agents_empty(task):
    assert list(task._batch_agents([])) == []


# ============================================================
# _get_max_versions_batch_from_indexer
# ============================================================
@pytest.mark.asyncio
async def test_get_max_versions_success(manager, logger):
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
    result = await task._get_max_versions_batch_from_indexer([])
    assert result == {}


@pytest.mark.asyncio
async def test_get_max_versions_indexer_error(manager, logger):
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


# ============================================================
# _get_disconnected_agents_filter_by_time
# ============================================================
@pytest.mark.asyncio
@patch("wazuh.core.indexer.disconnected_agents.WazuhDBQueryAgents")
@patch("wazuh.core.indexer.disconnected_agents.core_utils.get_utc_now")
async def test_get_disconnected_agents_filter_by_time_filters_by_time(
    mock_now, mock_query, task
):
    now = datetime.now(timezone.utc)
    mock_now.return_value = now

    agents = [
        {
            "id": "001",
            "status": "disconnected",
            "lastKeepAlive": now - timedelta(seconds=700),
            "group": ["default"],
        },
        {
            "id": "002",
            "status": "disconnected",
            "lastKeepAlive": now - timedelta(seconds=300),
            "group": ["default"],
        },
    ]

    db_instance = MagicMock()
    db_instance.run.return_value = {"items": agents}
    mock_query.return_value.__enter__.return_value = db_instance

    result = await task._get_disconnected_agents_filter_by_time()

    assert len(result) == 1
    assert result[0]["id"] == "001"


# ============================================================
# _sync_agent_batch
# ============================================================
@pytest.mark.asyncio
async def test_sync_agent_batch_success(task):
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
    agents = [{"id": "001"}]
    result = await task._sync_agent_batch(agents)

    assert result["processed"] == 0
    assert result["failed"] == 1


@pytest.mark.asyncio
async def test_sync_agent_batch_missing_id(task):
    agents = [{"group": ["default"]}]
    result = await task._sync_agent_batch(agents)

    assert result["processed"] == 0
    assert result["failed"] == 1


@pytest.mark.asyncio
async def test_sync_agent_batch_sync_error(task):
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
    """Returns agents disconnected longer than min_offline."""
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
    """Agents below min_offline threshold are ignored."""
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
    """Agents without lastKeepAlive are ignored safely."""
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
    """Empty DB result returns empty list."""
    db = MagicMock()
    db.run.return_value = {"items": []}
    mock_query.return_value.__enter__.return_value = db

    task = make_task()

    result = await task._get_disconnected_agents_filter_by_time()

    assert result == []


@pytest.mark.asyncio
@patch(
    "wazuh.core.indexer.disconnected_agents.WazuhDBQueryAgents",
    side_effect=Exception("DB error"),
)
async def test_db_error_returns_empty_list(mock_query):
    """DB errors are handled gracefully."""
    task = make_task()

    result = await task._get_disconnected_agents_filter_by_time()

    assert result == []
