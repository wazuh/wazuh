from unittest import mock

import pytest
from opensearchpy import exceptions
from wazuh.core.exception import WazuhError, WazuhResourceNotFound
from wazuh.core.indexer.base import IndexerKey
from wazuh.core.indexer.models.rbac import Rule
from wazuh.core.indexer.rules import RulesIndex


class TestRulesIndex:
    """Validate the correct functionality of the `RulesIndex` class."""

    index_class = RulesIndex
    rule = {
        'id': '0191480e-7f67-7fd3-8c52-f49a3176360b',
        'name': 'test',
        'body': {},
        'created_at': 0,
    }

    @pytest.fixture
    def client_mock(self) -> mock.AsyncMock:
        """Indexer client mock.

        Returns
        -------
        mock.AsyncMock
            Client mock.
        """
        return mock.AsyncMock()

    @pytest.fixture
    def index_instance(self, client_mock) -> RulesIndex:
        """Rules index mock.

        Parameters
        ----------
        client_mock : mock.AsyncMock
            Indexer client mock.

        Returns
        -------
        RulesIndex
            Rules index instance.
        """
        return self.index_class(client=client_mock)

    async def test_create(self, index_instance: RulesIndex, client_mock: mock.AsyncMock):
        """Validate the `create` method functionality."""
        new_rule = await index_instance.create(Rule(**self.rule))
        assert isinstance(new_rule, Rule)

        client_mock.index.assert_called_once_with(
            index=index_instance.INDEX,
            id=self.rule.get('id'),
            body={index_instance.KEY: new_rule.to_dict()},
            op_type='create',
            refresh='true',
        )

    async def test_create_ko(self, index_instance: RulesIndex, client_mock: mock.AsyncMock):
        """Validate the `create` method error handling."""
        client_mock.index.side_effect = exceptions.ConflictError

        with pytest.raises(WazuhError, match='.*4026.*'):
            await index_instance.create(Rule(**self.rule))

    async def test_delete(self, index_instance: RulesIndex, client_mock: mock.AsyncMock):
        """Validate the `delete` method functionality."""
        ids = ['0191480e-7f67-7fd3-8c52-f49a3176360b', '0191480e-7f67-7fd3-8c52-f49a3176360c']
        query = {IndexerKey.QUERY: {IndexerKey.TERMS: {IndexerKey._ID: ids}}}

        deleted_ids = await index_instance.delete(ids)

        assert ids == deleted_ids
        client_mock.delete_by_query.assert_called_once_with(
            index=index_instance.INDEX, body=query, conflicts='proceed', refresh='true'
        )

    async def test_get(self, index_instance: RulesIndex, client_mock: mock.AsyncMock):
        """Validate the `get` method functionality."""
        id = '0191480e-7f67-7fd3-8c52-f49a3176360b'
        name = 'test'
        body = {}
        get_result = {
            IndexerKey._ID: id,
            IndexerKey._SOURCE: {index_instance.KEY: {'id': id, 'name': name, 'body': {}}},
        }
        client_mock.get.return_value = get_result

        rule = await index_instance.get(id)

        assert Rule(id=id, name=name, body=body) == rule
        client_mock.get.assert_called_once_with(index=index_instance.INDEX, id=id)

    async def test_get_ko(self, index_instance: RulesIndex, client_mock: mock.AsyncMock):
        """Validate the `get` method error handling."""
        client_mock.get.side_effect = exceptions.NotFoundError

        with pytest.raises(WazuhResourceNotFound, match='.*4027.*'):
            await index_instance.get(Rule(**self.rule))

    async def test_search(self, index_instance: RulesIndex, client_mock: mock.AsyncMock):
        """Validate the `search` method functionality."""
        query = {'foo': 1, 'bar': 2}
        select = 'id'
        exclude = 'key'
        limit = 10
        offset = 1
        sort = 'name'
        search_result = [
            {index_instance.KEY: {'id': '0191dd54-bd16-7025-80e6-ae49bc101c7a', 'name': 'test', 'body': {}}}
        ]
        client_mock.search.return_value = search_result

        with mock.patch('wazuh.core.indexer.rbac.get_source_items', return_value=search_result):
            result = await index_instance.search(
                query=query, select=select, exclude=exclude, limit=limit, offset=offset, sort=sort
            )

        assert result == [Rule(**item[index_instance.KEY]) for item in search_result]
        client_mock.search.assert_called_once_with(
            index=index_instance.INDEX,
            body=query,
            _source_includes=select,
            _source_excludes=exclude,
            size=limit,
            from_=offset,
            sort=sort,
        )

    async def test_update(self, index_instance: RulesIndex, client_mock: mock.AsyncMock):
        """Validate the `update` method functionality."""
        id = '0191c22a-da10-79bd-9c47-818bc1c03065'
        new_name = 'foo'

        await index_instance.update(id=id, rule=Rule(name=new_name))

        query = {IndexerKey.DOC: {index_instance.KEY: {'name': new_name}}}
        client_mock.update.assert_called_once_with(index=index_instance.INDEX, id=id, body=query)
