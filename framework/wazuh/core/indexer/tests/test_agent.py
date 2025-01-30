from unittest import mock

import pytest
from opensearchpy import exceptions
from opensearchpy.helpers.response import Hit

from wazuh.core.exception import WazuhError
from wazuh.core.indexer.agent import AgentsIndex, AGENT_KEY
from wazuh.core.indexer.base import IndexerKey
from wazuh.core.indexer.models.agent import Agent


class TestAgentIndex:
    index_class = AgentsIndex
    create_id = '0191480e-7f67-7fd3-8c52-f49a3176360b'
    create_params = {
        'name': 'test',
        'key': '015fb915771223a3fdd7c0c0a5adcab8',
        'type': 'endpoint',
        'version': '5.0.0',
    }

    @pytest.fixture
    def client_mock(self) -> mock.AsyncMock:
        return mock.AsyncMock()

    @pytest.fixture
    def index_instance(self, client_mock) -> AgentsIndex:
        return self.index_class(client=client_mock)

    async def test_create(self, index_instance: AgentsIndex, client_mock: mock.AsyncMock):
        """Check the correct function of `create` method."""
        new_agent = await index_instance.create(id=self.create_id, **self.create_params)

        assert isinstance(new_agent, Agent)
        client_mock.index.assert_called_once_with(
            index=index_instance.INDEX,
            id=self.create_id,
            body={AGENT_KEY: new_agent.to_dict()},
            op_type='create',
            refresh='true'
        )

    async def test_create_ko(self, index_instance: AgentsIndex, client_mock: mock.AsyncMock):
        """Check the correct raise of `create` method."""
        client_mock.index.side_effect = exceptions.ConflictError

        with pytest.raises(WazuhError, match='.*1708.*'):
            await index_instance.create(id=self.create_id, **self.create_params)

    async def test_delete(self, index_instance: AgentsIndex, client_mock: mock.AsyncMock):
        """Check the correct function of `delete` method"""
        ids = ['0191480e-7f67-7fd3-8c52-f49a3176360b', '0191480e-7f67-7fd3-8c52-f49a3176360c']
        indexes = ','.join([index_instance.INDEX, *index_instance.SECONDARY_INDEXES])
        query = {IndexerKey.QUERY: {IndexerKey.TERMS: {IndexerKey._ID: ids}}}

        deleted_ids = await index_instance.delete(ids)

        assert ids == deleted_ids
        client_mock.delete_by_query.assert_called_once_with(
            index=indexes, body=query, conflicts='proceed', refresh='true'
        )

    async def test_search(self, index_instance: AgentsIndex, client_mock: mock.AsyncMock):
        """Check the correct function of `search` method."""
        query = {'foo': 1, 'bar': 2}
        select = 'id'
        exclude = 'key'
        limit = 10
        offset = 1
        sort = 'name'
        search_result = [{AGENT_KEY: {'name': 'test', 'id': '0191dd54-bd16-7025-80e6-ae49bc101c7a'}}]
        client_mock.search.return_value = search_result

        with mock.patch('wazuh.core.indexer.agent.get_source_items', return_value=search_result):
            result = await index_instance.search(
                query=query, select=select, exclude=exclude, limit=limit, offset=offset, sort=sort
            )

        assert result == [Agent(**item[AGENT_KEY]) for item in search_result]
        client_mock.search.assert_called_once_with(
            index=index_instance.INDEX,
            body=query,
            _source_includes=select,
            _source_excludes=exclude,
            size=limit,
            from_=offset,
            sort=sort
        )

    async def test_update(self, index_instance: AgentsIndex, client_mock: mock.AsyncMock):
        """Check the correct function of `update` method."""
        uuid = '0191c22a-da10-79bd-9c47-818bc1c03065'
        new_name = 'foo'

        await index_instance.update(uuid=uuid, agent=Agent(name=new_name))

        query = {IndexerKey.DOC: {AGENT_KEY: {'name': new_name}}}
        client_mock.update.assert_called_once_with(index=index_instance.INDEX, id=uuid, body=query)

    async def test_delete_group(self, index_instance: AgentsIndex, client_mock: mock.AsyncMock):
        """Check the correct function of `delete_group` method."""
        group_name = 'foo'
        await index_instance.delete_group(group_name=group_name)

        query = {
            IndexerKey.QUERY: {
                IndexerKey.BOOL: {
                    IndexerKey.FILTER: [{
                        IndexerKey.TERM: {
                            'agent.groups': group_name
                        }
                    }]
                }
            },
            'script': {
                'source': AgentsIndex.REMOVE_GROUP_SCRIPT,
                'lang': 'painless',
                'params': {
                    'group': group_name
                }
            }
        }
        client_mock.update_by_query.assert_called_once_with(index=[index_instance.INDEX], body=query)

    async def test_get_group_agents(self, index_instance: AgentsIndex, client_mock: mock.AsyncMock):
        """Check the correct function of `get_group_agents` method."""
        group_name = 'foo'
        agent_id = '0191c248-095c-75e6-89ec-612fa5727c2e'
        search_result = {'_hits': [Hit({IndexerKey._SOURCE: {AGENT_KEY: {'id': agent_id}}})]}
        client_mock.search.return_value = search_result
        expected_result = [Agent(id=agent_id)]

        result = await index_instance.get_group_agents(group_name=group_name)

        query = {
            IndexerKey.QUERY: {
                IndexerKey.BOOL: {
                    IndexerKey.FILTER: [{
                        IndexerKey.TERM: {
                            'agent.groups': group_name
                        }
                    }]
                }
            }
        }
        client_mock.search.assert_called_once_with(index=[index_instance.INDEX], body=query)

        assert result == expected_result

    @pytest.mark.parametrize('override', [False, True])
    async def test_add_agents_to_group(self, index_instance: AgentsIndex, override):
        """Check the correct function of `add_agents_to_group` method."""
        group_name = 'foo'
        agent_ids = ['0191c234-6dfa-7776-807a-2e38fbf42c5b', '0191c234-6dfa-747d-97af-4d8f2220252d']

        with mock.patch('wazuh.core.indexer.agent.AgentsIndex._update_groups') as mock_update:
            await index_instance.add_agents_to_group(group_name=group_name, agent_ids=agent_ids, override=override)

        mock_update.assert_called_once_with(group_name=group_name, agent_ids=agent_ids, override=override)

    async def test_remove_agents_from_group(self, index_instance: AgentsIndex):
        """Check the correct function of `remove_agents_from_group` method."""
        group_name = 'foo'
        agent_ids = ['0191c234-6dfa-7776-807a-2e38fbf42c5b', '0191c234-6dfa-747d-97af-4d8f2220252d']

        with mock.patch('wazuh.core.indexer.agent.AgentsIndex._update_groups') as mock_update:
            await index_instance.remove_agents_from_group(group_name=group_name, agent_ids=agent_ids)

        mock_update.assert_called_once_with(group_name=group_name, agent_ids=agent_ids, remove=True)

    @pytest.mark.parametrize('override', [False, True])
    async def test__update_groups_add(self, index_instance: AgentsIndex, client_mock: mock.AsyncMock, override):
        """Check the correct function of `_update_groups` method."""
        group_name = 'foo'
        agent_ids = ['0191c234-6dfa-7776-807a-2e38fbf42c5b', '0191c234-6dfa-747d-97af-4d8f2220252d']
        await index_instance._update_groups(group_name=group_name, agent_ids=agent_ids, override=override)

        if override:
            source = 'ctx._source.agent.groups = new String[] {params.group};'
        else:
            # Changing the indentation makes the test fail
            source = """
                if (ctx._source.agent.groups == null) {
                    ctx._source.agent.groups = new String[] {params.group};
                } else {
                    ctx._source.agent.groups.add(params.group);
                }
                """

        query = {
            IndexerKey.QUERY: {
                IndexerKey.BOOL: {
                    IndexerKey.FILTER: [{
                        IndexerKey.IDS: {
                            'values': agent_ids
                        }
                    }]
                }
            },
            'script': {
                'source': source,
                'lang': 'painless',
                'params': {
                    'group': group_name
                }
            }
        }
        client_mock.update_by_query.assert_called_once_with(index=[index_instance.INDEX], body=query)

    async def test__update_groups_remove(self, index_instance: AgentsIndex, client_mock: mock.AsyncMock):
        """Check the correct function of `_update_groups` method."""
        group_name = 'foo'
        agent_ids = ['0191c234-6dfa-7776-807a-2e38fbf42c5b', '0191c234-6dfa-747d-97af-4d8f2220252d']
        await index_instance._update_groups(group_name=group_name, agent_ids=agent_ids, remove=True)

        query = {
            IndexerKey.QUERY: {
                IndexerKey.BOOL: {
                    IndexerKey.FILTER: [{
                        IndexerKey.IDS: {
                            'values': agent_ids
                        }
                    }]
                }
            },
            'script': {
                'source': AgentsIndex.REMOVE_GROUP_SCRIPT,
                'lang': 'painless',
                'params': {
                    'group': group_name
                }
            }
        }
        client_mock.update_by_query.assert_called_once_with(index=[index_instance.INDEX], body=query)
