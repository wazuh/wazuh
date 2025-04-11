from unittest import mock

import pytest
from opensearchpy import exceptions
from wazuh.core.exception import WazuhResourceNotFound
from wazuh.core.indexer.base import IndexerKey
from wazuh.core.indexer.models.rbac import User
from wazuh.core.indexer.users import UsersIndex


class TestUsersIndex:
    """Validate the correct functionality of the `UsersIndex` class."""

    index_class = UsersIndex
    user = {
        'id': '0191480e-7f67-7fd3-8c52-f49a3176360b',
        'name': 'test',
        'password': 'test',
        'allow_run_as': False,
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
    def index_instance(self, client_mock) -> UsersIndex:
        """Users index mock.

        Parameters
        ----------
        client_mock : mock.AsyncMock
            Indexer client mock.

        Returns
        -------
        UsersIndex
            Users index instance.
        """
        return self.index_class(client=client_mock)

    async def test_get(self, index_instance: UsersIndex, client_mock: mock.AsyncMock):
        """Validate the `get` method functionality."""
        id = '0191480e-7f67-7fd3-8c52-f49a3176360b'
        name = 'test'
        allow_run_as = False
        get_result = {
            IndexerKey._ID: id,
            IndexerKey._SOURCE: {index_instance.KEY: {'id': id, 'name': name, 'allow_run_as': allow_run_as}},
        }
        client_mock.get.return_value = get_result

        user = await index_instance.get(id)

        assert User(id=id, name=name, allow_run_as=allow_run_as) == user
        client_mock.get.assert_called_once_with(index=index_instance.INTERNAL_INDEX, id=id)

    async def test_get_ko(self, index_instance: UsersIndex, client_mock: mock.AsyncMock):
        """Validate the `get` method error handling."""
        client_mock.get.side_effect = exceptions.NotFoundError

        with pytest.raises(WazuhResourceNotFound, match='.*4027.*'):
            await index_instance.get(User(**self.user))

    async def test_search(self, index_instance: UsersIndex, client_mock: mock.AsyncMock):
        """Validate the `search` method functionality."""
        query = {'foo': 1, 'bar': 2}
        select = 'id'
        exclude = 'key'
        limit = 10
        offset = 1
        sort = 'name'
        search_result = [
            {index_instance.KEY: {'id': '0191dd54-bd16-7025-80e6-ae49bc101c7a', 'name': 'test', 'allow_run_as': False}}
        ]
        client_mock.search.return_value = search_result

        with mock.patch('wazuh.core.indexer.users.get_source_items', return_value=search_result):
            result = await index_instance.search(
                query=query, select=select, exclude=exclude, limit=limit, offset=offset, sort=sort
            )

        client_mock.search.assert_has_calls(
            [
                mock.call(
                    index=index_instance.INTERNAL_INDEX,
                    body=query,
                    _source_includes=select,
                    _source_excludes=exclude,
                    sort=sort,
                    size=limit,
                ),
                mock.call(
                    index=index_instance.INDEX,
                    body=query,
                    _source_includes=select,
                    _source_excludes=exclude,
                    size=limit,
                    from_=offset,
                    sort=sort,
                ),
            ]
        )
        assert result == [User(**item[index_instance.KEY]) for item in search_result * 2]
