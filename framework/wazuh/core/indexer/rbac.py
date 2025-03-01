from typing import Union

from opensearchpy import AsyncOpenSearch, exceptions
from pydantic.type_adapter import TypeAdapter
from wazuh.core.exception import WazuhError, WazuhResourceNotFound
from wazuh.core.indexer.base import BaseIndex, IndexerKey
from wazuh.core.indexer.models.rbac import Policy, Role, Rule, User
from wazuh.core.indexer.utils import get_source_items

Entity = Union[Policy, Role, Rule, User]


class RBACIndex(BaseIndex):
    """Set of methods to interact with the RBAC indices."""

    KEY = None
    INDEX = None

    def __init__(self, client: AsyncOpenSearch) -> None:
        BaseIndex.__init__(self, client)

        if self.KEY is None or self.INDEX is None:
            raise NotImplementedError

    async def create(self, entity: Entity) -> Entity:
        """Create a new entity.

        Parameters
        ----------
        entity : RBACEntity
            Entity instance containing its details.

        Raises
        ------
        WazuhError(4026)
            If a entity with the provided ID already exists.

        Returns
        -------
        RBACEntity
            The created entity instance.
        """
        try:
            await self._client.index(
                index=self.INDEX, id=entity.id, body={self.KEY: entity.to_dict()}, op_type='create', refresh='true'
            )
        except exceptions.ConflictError:
            extra_info = {'entity': self.KEY, 'id': entity.id}
            raise WazuhError(4026, extra_message=extra_info)

        return entity

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

    async def get(self, id: str) -> Entity:
        """Retrieve an entity.

        Parameters
        ----------
        id : str
            Entity identifier.

        Raises
        ------
        WazuhResourceNotFound(4027)
            If no entities exist with the UUID provided.

        Returns
        -------
        RBACEntity
            Entity object.
        """
        try:
            data = await self._client.get(index=self.INDEX, id=id)
        except exceptions.NotFoundError:
            extra_info = {
                'entity': self.KEY.title(),
                'entities': self.INDEX,
            }
            raise WazuhResourceNotFound(4027, extra_message=extra_info)

        return TypeAdapter(Entity).validate_python(data[IndexerKey._SOURCE][self.KEY])

    async def search(
        self,
        query: dict,
        select: str | None = None,
        exclude: str | None = None,
        offset: int | None = None,
        limit: int | None = None,
        sort: str | None = None,
    ) -> list[Entity]:
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
        return [TypeAdapter(Entity).validate_python(item[self.KEY]) for item in get_source_items(results)]

    async def update(self, id: str, entity: Entity) -> None:
        """Update an entity.

        Parameters
        ----------
        id : str
            Entity identifier.
        entity : RBACEntity
            Entity fields. Only specified fields are updated.

        Raises
        ------
        WazuhResourceNotFound(4027)
            If no entities exist with the UUID provided.
        """
        try:
            body = {IndexerKey.DOC: {self.KEY: entity.to_dict()}}
            await self._client.update(index=self.INDEX, id=id, body=body)
        except exceptions.NotFoundError:
            extra_info = {
                'entity': self.KEY.title(),
                'entities': self.INDEX,
            }
            raise WazuhResourceNotFound(4027, extra_message=extra_info)
