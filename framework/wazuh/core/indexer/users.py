from opensearchpy import exceptions
from wazuh.core.exception import WazuhResourceNotFound
from wazuh.core.indexer.base import BaseIndex, IndexerKey
from wazuh.core.indexer.models.rbac import User
from wazuh.core.indexer.utils import get_source_items


class UsersIndex(BaseIndex):
    """Set of methods to interact with the `users` index."""

    INTERNAL_INDEX = 'wazuh-internal-users'
    INDEX = 'wazuh-custom-users'
    KEY = 'user'

    async def get(self, id: str) -> User:
        """Retrieve a user.

        Parameters
        ----------
        id : str
            User identifier.

        Raises
        ------
        WazuhResourceNotFound(4027)
            If no users exist with the UUID provided.

        Returns
        -------
        User
            User object.
        """
        try:
            data = await self._client.get(index=self.INTERNAL_INDEX, id=id)
        except exceptions.NotFoundError:
            # If the user does not exist in the internal index, search for it in the custom one
            try:
                data = await self._client.get(index=self.INDEX, id=id)
            except exceptions.NotFoundError:
                extra_info = {
                    'entity': self.KEY.title(),
                    'entities': f'{self.KEY}s',
                }
                raise WazuhResourceNotFound(4027, extra_message=extra_info)

        return User(**data[IndexerKey._SOURCE][self.KEY])

    async def search(
        self,
        query: dict,
        select: str | None = None,
        exclude: str | None = None,
        offset: int | None = None,
        limit: int | None = None,
        sort: str | None = None,
    ) -> list[User]:
        """Perform a search operation with the given query.

        Parameters
        ----------
        query : dict
            DSL query.
        select : str | None
            A comma-separated list of fields to include in the response, by default None.
        exclude : str | None
            A comma-separated list of fields to exclude from the response, by default None.
        offset : int | None
            The starting index to search from, by default None.
        limit : int | None
            How many results to include in the response, by default None.
        sort : str | None
            A comma-separated list of fields to sort by, by default None.

        Returns
        -------
        dict
            The search result.
        """
        internal_users = await self._client.search(
            index=self.INTERNAL_INDEX,
            body=query,
            _source_includes=select,
            _source_excludes=exclude,
            sort=sort,
            size=limit,
        )
        custom_users = await self._client.search(
            index=self.INDEX,
            body=query,
            _source_includes=select,
            _source_excludes=exclude,
            size=limit,
            from_=offset,
            sort=sort,
        )

        users: list[User] = []
        for item in get_source_items(internal_users):
            users.append(User(**item[self.KEY]))

        for item in get_source_items(custom_users):
            users.append(User(**item[self.KEY]))

        return users
