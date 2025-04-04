from datetime import datetime, timezone

from opensearchpy import exceptions
from wazuh.core.exception import WazuhError, WazuhResourceNotFound
from wazuh.core.indexer.base import BaseIndex, IndexerKey
from wazuh.core.indexer.models.rbac import User
from wazuh.core.indexer.utils import get_source_items


class UsersIndex(BaseIndex):
    """Set of methods to interact with the `users` index."""

    INTERNAL_INDEX = 'wazuh-internal-users'
    INDEX = 'wazuh-custom-users'
    KEY = 'user'

    async def create(
        self,
        id: str,
        name: str,
        password: str,
        allow_run_as: bool,
    ) -> User:
        """Create a new user.

        Parameters
        ----------
        id : str
            User ID.
        name : str
            User name.
        password : str
            User password.
        allow_run_as : bool
            Allow running as other users.

        Raises
        ------
        WazuhError(4026)
            If a user with the provided ID already exists.

        Returns
        -------
        User
            The created user instance.
        """
        now = datetime.now(timezone.utc)
        user = User(id=id, name=name, raw_password=password, allow_run_as=allow_run_as, created_at=now)

        try:
            await self._client.index(
                index=self.INDEX, id=user.id, body={self.KEY: user.to_dict()}, op_type='create', refresh='true'
            )
        except exceptions.ConflictError:
            extra_info = {'entity': self.KEY, 'id': user.id}
            raise WazuhError(4026, extra_message=extra_info)

        return user

    async def delete(self, ids: list[str]) -> list[str]:
        """Delete multiple entities that match with the given parameters.

        Parameters
        ----------
        ids : list[str]
            Entity identifiers.

        Returns
        -------
        list[str]
            Deleted entity IDs.
        """
        body = {IndexerKey.QUERY: {IndexerKey.TERMS: {IndexerKey._ID: ids}}}
        parameters = {IndexerKey.INDEX: self.INDEX, IndexerKey.BODY: body, IndexerKey.CONFLICTS: 'proceed'}

        await self._client.delete_by_query(**parameters, refresh='true')

        return ids

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

    async def update(
        self,
        id: str,
        name: str = None,
        password: str = None,
        allow_run_as: bool = None,
    ) -> None:
        """Update a user.

        Parameters
        ----------
        id : str
            User identifier.
        name : str
            User name.
        password : str
            User password.
        allow_run_as : bool
            Allow running as other users.
        """
        user = User(id=id, name=name, raw_password=password, allow_run_as=allow_run_as)
        try:
            body = {IndexerKey.DOC: {self.KEY: user.to_dict()}}
            await self._client.update(index=self.INDEX, id=id, body=body)
        except exceptions.NotFoundError:
            extra_info = {
                'entity': self.KEY.title(),
                'entities': f'{self.KEY}s',
            }
            raise WazuhResourceNotFound(4027, extra_message=extra_info)
