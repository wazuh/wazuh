from datetime import datetime, timezone

from opensearchpy import exceptions
from wazuh.core.exception import WazuhError
from wazuh.core.indexer.models.rbac import User
from wazuh.core.indexer.rbac import RBACIndex


class UsersIndex(RBACIndex):
    """Set of methods to interact with the `users` index."""

    INDEX = 'wazuh-users'
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
        return await super().get(id)

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
        return await super().search(query, select, exclude, offset, limit, sort)

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
        await super().update(id, user)
