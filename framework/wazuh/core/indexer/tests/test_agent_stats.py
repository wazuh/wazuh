# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

"""
Unit tests for AgentStatsIndex reads.
"""

from unittest.mock import AsyncMock

import pytest

from wazuh.core.indexer.agent_stats import AGENT_STATS_INDEX, AgentStatsIndex

LOGCOLLECTOR_STATS = {'global': {'files': []}, 'interval': {'files': []}}


@pytest.fixture
def mock_indexer_client():
    """Create a mock AsyncOpenSearch client."""
    return AsyncMock()


@pytest.fixture
def agent_stats_index(mock_indexer_client):
    """Create AgentStatsIndex instance with mock client."""
    return AgentStatsIndex(client=mock_indexer_client)


def _doc(agent_id: str, component: str, stats: dict) -> dict:
    return {'_id': agent_id, 'found': True, '_source': {'wazuh': {'agent': {'statistics': {component: stats}}}}}


def test_index_name_is_stable():
    """The name is a wire contract with modulesd, which declares the same literal in C++."""
    assert AGENT_STATS_INDEX == 'wazuh-agent-stats'


@pytest.mark.asyncio
async def test_get_component_reads_by_document_id(agent_stats_index, mock_indexer_client):
    """The whole list is one mget, with _source trimmed to the requested component."""
    mock_indexer_client.mget.return_value = {'docs': [_doc('001', 'logcollector', LOGCOLLECTOR_STATS)]}

    result = await agent_stats_index.get_component(['001'], 'logcollector')

    assert result == {'001': LOGCOLLECTOR_STATS}
    mock_indexer_client.mget.assert_awaited_once_with(
        index=AGENT_STATS_INDEX,
        body={'ids': ['001']},
        _source=['wazuh.agent.statistics.logcollector'],
    )


@pytest.mark.asyncio
@pytest.mark.parametrize('document', [
    {'_id': '001', 'found': False},
    {'_id': '001', 'found': True, '_source': {'wazuh': {'agent': {'statistics': {}}}}},
])
async def test_get_component_returns_none_without_usable_stats(agent_stats_index, mock_indexer_client, document):
    """No document and a document without that component read the same to the caller."""
    mock_indexer_client.mget.return_value = {'docs': [document]}

    assert await agent_stats_index.get_component(['001'], 'logcollector') == {'001': None}


@pytest.mark.asyncio
async def test_get_component_keeps_every_requested_id(agent_stats_index, mock_indexer_client):
    """Every requested id is in the mapping, so the caller never distinguishes absent from None."""
    mock_indexer_client.mget.return_value = {
        'docs': [{'_id': '001', 'found': False}, _doc('002', 'agent', {'messages': {'count': 1}})]
    }

    result = await agent_stats_index.get_component(['001', '002'], 'agent')

    assert result == {'001': None, '002': {'messages': {'count': 1}}}


@pytest.mark.asyncio
async def test_get_component_ignores_documents_that_were_not_requested(agent_stats_index, mock_indexer_client):
    """A response carrying an id nobody asked for must not widen the result."""
    mock_indexer_client.mget.return_value = {
        'docs': [_doc('001', 'agent', {'messages': {'count': 1}}), _doc('999', 'agent', {'messages': {'count': 2}})]
    }

    assert await agent_stats_index.get_component(['001'], 'agent') == {'001': {'messages': {'count': 1}}}
