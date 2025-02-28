from unittest import mock

import pytest
from opensearchpy import exceptions
from wazuh.core.exception import WazuhError, WazuhResourceNotFound
from wazuh.core.indexer.base import IndexerKey
from wazuh.core.indexer.models.rbac import Role
from wazuh.core.indexer.roles import ROLE_KEY, RolesIndex


class TestRolesIndex:
    """Validate the correct functionality of the `RolesIndex` class."""

    index_class = RolesIndex
    role = {
        'id': '0191480e-7f67-7fd3-8c52-f49a3176360b',
        'name': 'test',
        'level': 1,
        'policies': [{'id': '1'}],
        'rules': [{'id': '1'}],
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
    def index_instance(self, client_mock) -> RolesIndex:
        """Roles index mock.

        Parameters
        ----------
        client_mock : mock.AsyncMock
            Indexer client mock.

        Returns
        -------
        RolesIndex
            Roles index instance.
        """
        return self.index_class(client=client_mock)

    async def test_create(self, index_instance: RolesIndex, client_mock: mock.AsyncMock):
        """Validate the `create` method functionality."""
        new_role = await index_instance.create(Role(**self.role))
        assert isinstance(new_role, Role)

        client_mock.index.assert_called_once_with(
            index=index_instance.INDEX,
            id=self.role.get('id'),
            body={ROLE_KEY: new_role.to_dict()},
            op_type='create',
            refresh='true',
        )

    async def test_create_ko(self, index_instance: RolesIndex, client_mock: mock.AsyncMock):
        """Validate the `create` method error handling."""
        client_mock.index.side_effect = exceptions.ConflictError

        with pytest.raises(WazuhError, match='.*4028.*'):
            await index_instance.create(Role(**self.role))

    async def test_delete(self, index_instance: RolesIndex, client_mock: mock.AsyncMock):
        """Validate the `delete` method functionality."""
        ids = ['0191480e-7f67-7fd3-8c52-f49a3176360b', '0191480e-7f67-7fd3-8c52-f49a3176360c']
        query = {IndexerKey.QUERY: {IndexerKey.TERMS: {IndexerKey._ID: ids}}}

        deleted_ids = await index_instance.delete(ids)

        assert ids == deleted_ids
        client_mock.delete_by_query.assert_called_once_with(
            index=index_instance.INDEX, body=query, conflicts='proceed', refresh='true'
        )

    async def test_get(self, index_instance: RolesIndex, client_mock: mock.AsyncMock):
        """Validate the `get` method functionality."""
        id = '0191480e-7f67-7fd3-8c52-f49a3176360b'
        name = 'test'
        get_result = {IndexerKey._ID: id, IndexerKey._SOURCE: {ROLE_KEY: {'id': id, 'name': name}}}
        client_mock.get.return_value = get_result

        role = await index_instance.get(id)

        assert Role(id=id, name=name) == role
        client_mock.get.assert_called_once_with(index=index_instance.INDEX, id=id)

    async def test_get_ko(self, index_instance: RolesIndex, client_mock: mock.AsyncMock):
        """Validate the `get` method error handling."""
        client_mock.get.side_effect = exceptions.NotFoundError

        with pytest.raises(WazuhResourceNotFound, match='.*4029.*'):
            await index_instance.get(Role(**self.role))

    async def test_search(self, index_instance: RolesIndex, client_mock: mock.AsyncMock):
        """Validate the `search` method functionality."""
        query = {'foo': 1, 'bar': 2}
        select = 'id'
        exclude = 'key'
        limit = 10
        offset = 1
        sort = 'name'
        search_result = [{ROLE_KEY: {'name': 'test', 'id': '0191dd54-bd16-7025-80e6-ae49bc101c7a'}}]
        client_mock.search.return_value = search_result

        with mock.patch('wazuh.core.indexer.roles.get_source_items', return_value=search_result):
            result = await index_instance.search(
                query=query, select=select, exclude=exclude, limit=limit, offset=offset, sort=sort
            )

        assert result == [Role(**item[ROLE_KEY]) for item in search_result]
        client_mock.search.assert_called_once_with(
            index=index_instance.INDEX,
            body=query,
            _source_includes=select,
            _source_excludes=exclude,
            size=limit,
            from_=offset,
            sort=sort,
        )

    async def test_update(self, index_instance: RolesIndex, client_mock: mock.AsyncMock):
        """Validate the `update` method functionality."""
        id = '0191c22a-da10-79bd-9c47-818bc1c03065'
        new_name = 'foo'

        await index_instance.update(id=id, role=Role(name=new_name))

        query = {IndexerKey.DOC: {ROLE_KEY: {'name': new_name}}}
        client_mock.update.assert_called_once_with(index=index_instance.INDEX, id=id, body=query)
