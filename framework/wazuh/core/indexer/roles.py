from opensearchpy import exceptions
from wazuh.core.exception import WazuhError, WazuhResourceNotFound
from wazuh.core.indexer.base import BaseIndex, IndexerKey
from wazuh.core.indexer.models.roles import Role
from wazuh.core.indexer.utils import get_source_items

ROLE_KEY = 'role'


class RolesIndex(BaseIndex):
    """Set of methods to interact with the `roles` index."""

    INDEX = 'roles'

    async def create(self, role: Role) -> Role:
        """Create a new role.

        Parameters
        ----------
        role : Role
            Role instance containing its details.

        Raises
        ------
        WazuhError(4026)
            If a role with the provided ID already exists.

        Returns
        -------
        Role
            The created role instance.
        """
        try:
            await self._client.index(
                index=self.INDEX, id=role.id, body={ROLE_KEY: role.to_dict()}, op_type='create', refresh='true'
            )
        except exceptions.ConflictError:
            raise WazuhError(4026, extra_message=role.id)

        return role

    async def delete(self, ids: list[str]) -> list[str]:
        """Delete multiple roles that match with the given parameters.

        Parameters
        ----------
        ids : list[str]
            Role identifiers.

        Returns
        -------
        list[str]
            Deleted role IDs.
        """
        body = {IndexerKey.QUERY: {IndexerKey.TERMS: {IndexerKey._ID: ids}}}
        parameters = {IndexerKey.INDEX: self.INDEX, IndexerKey.BODY: body, IndexerKey.CONFLICTS: 'proceed'}

        await self._client.delete_by_query(**parameters, refresh='true')

        return ids

    async def get(self, id: str) -> Role:
        """Retrieve a role.

        Parameters
        ----------
        id : str
            Role identifier.

        Raises
        ------
        WazuhResourceNotFound(4027)
            If no roles exist with the UUID provided.

        Returns
        -------
        Role
            Role object.
        """
        try:
            data = await self._client.get(index=self.INDEX, id=id)
        except exceptions.NotFoundError:
            raise WazuhResourceNotFound(4027)

        return Role(**data[IndexerKey._SOURCE][ROLE_KEY])

    async def search(
        self,
        query: dict,
        select: str | None = None,
        exclude: str | None = None,
        offset: int | None = None,
        limit: int | None = None,
        sort: str | None = None,
    ) -> list[Role]:
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
        return [Role(**item[ROLE_KEY]) for item in get_source_items(results)]

    async def update(self, id: str, role: Role) -> None:
        """Update a role.

        Parameters
        ----------
        id : str
            Role identifier.
        role : Role
            Role fields. Only specified fields are updated.

        Raises
        ------
        WazuhResourceNotFound(4027)
            If no roles exist with the UUID provided.
        """
        try:
            body = {IndexerKey.DOC: {ROLE_KEY: role.to_dict()}}
            await self._client.update(index=self.INDEX, id=id, body=body)
        except exceptions.NotFoundError:
            raise WazuhResourceNotFound(4027)
