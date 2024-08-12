from dataclasses import asdict
from unittest import mock

import pytest
from opensearchpy import exceptions
from wazuh.core.exception import WazuhError
from wazuh.core.indexer.agent import AgentsIndex
from wazuh.core.indexer.constants import QUERY_KEY, TERMS_KEY
from wazuh.core.indexer.models import Agent


class TestAgentIndex:
    index_class = AgentsIndex
    create_params = {
        'id': '0191480e-7f67-7fd3-8c52-f49a3176360b',
        'name': 'test',
        'key': '015fb915771223a3fdd7c0c0a5adcab8',
    }

    @pytest.fixture
    def client_mock(self) -> mock.AsyncMock:
        return mock.AsyncMock()

    @pytest.fixture
    def index_instance(self, client_mock) -> AgentsIndex:
        return self.index_class(client=client_mock)

    async def test_create(self, index_instance: AgentsIndex, client_mock: mock.AsyncMock):
        """Check the correct function of `create` method"""
        new_agent = await index_instance.create(**self.create_params)

        assert isinstance(new_agent, Agent)
        client_mock.index.assert_called_once_with(
            index=index_instance.INDEX, id=new_agent.id, body=asdict(new_agent), op_type='create', refresh='wait_for'
        )

    async def test_create_ko(self, index_instance: AgentsIndex, client_mock: mock.AsyncMock):
        """Check the correct raise of `create` method"""
        client_mock.index.side_effect = exceptions.ConflictError

        with pytest.raises(WazuhError, match='.*1708.*'):
            await index_instance.create(**self.create_params)

    async def test_delete(self, index_instance: AgentsIndex, client_mock: mock.AsyncMock):
        """Check the correct function of `delete` method"""
        ids = ['0191480e-7f67-7fd3-8c52-f49a3176360b', '0191480e-7f67-7fd3-8c52-f49a3176360c']
        indexes = ','.join([index_instance.INDEX, *index_instance.SECONDARY_INDEXES])
        query = {QUERY_KEY: {TERMS_KEY: {'_id': ids}}}

        deleted_ids = await index_instance.delete(ids)

        assert ids == deleted_ids
        client_mock.delete_by_query.assert_called_once_with(
            index=indexes, body=query, conflicts='proceed', refresh='true'
        )

    async def test_search(self, index_instance: AgentsIndex, client_mock: mock.AsyncMock):
        """Check the correct function of `search` method"""
        query = {'foo': 1, 'bar': 2}
        search_result = {'baz': 3}
        client_mock.search.return_value = search_result

        result = await index_instance.search(query=query)

        assert result == search_result
        client_mock.search.assert_called_once_with(index=index_instance.INDEX, body=query)
