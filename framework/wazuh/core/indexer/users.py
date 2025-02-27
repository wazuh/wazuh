from datetime import datetime, timezone

from opensearchpy import exceptions
from wazuh.core.exception import WazuhError, WazuhResourceNotFound
from wazuh.core.indexer.base import BaseIndex, IndexerKey
from wazuh.core.indexer.models.user import User
from wazuh.core.indexer.utils import get_source_items

USER_KEY = 'user'


class UsersIndex(BaseIndex):
    """Set of methods to interact with the `users` index."""

    INDEX = 'users'

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
                index=self.INDEX, id=user.id, body={USER_KEY: user.to_dict()}, op_type='create', refresh='true'
            )
        except exceptions.ConflictError:
            raise WazuhError(4026, extra_message=user.id)

        return user

    async def delete(self, ids: list[str]) -> list[str]:
        """Delete multiple users that match with the given parameters.

        Parameters
        ----------
        ids : list[str]
            User identifiers.

        Returns
        -------
        list[str]
            Deleted user IDs.
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
            data = await self._client.get(index=self.INDEX, id=id)
        except exceptions.NotFoundError:
            raise WazuhResourceNotFound(4027)

        return User(**data[IndexerKey._SOURCE][USER_KEY])

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
        parameters = {IndexerKey.INDEX: self.INDEX, IndexerKey.BODY: query}
        results = await self._client.search(
            **parameters, _source_includes=select, _source_excludes=exclude, size=limit, from_=offset, sort=sort
        )
        return [User(**item[USER_KEY]) for item in get_source_items(results)]

    async def update(self, id: str, user: User) -> None:
        """Update a user.

        Parameters
        ----------
        id : str
            User identifier.
        user : User
            User fields. Only specified fields are updated.

        Raises
        ------
        WazuhResourceNotFound(4027)
            If no users exist with the UUID provided.
        """
        try:
            body = {IndexerKey.DOC: {USER_KEY: user.to_dict()}}
            await self._client.update(index=self.INDEX, id=id, body=body)
        except exceptions.NotFoundError:
            raise WazuhResourceNotFound(4027)
