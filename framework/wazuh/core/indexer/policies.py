from opensearchpy import exceptions
from wazuh.core.exception import WazuhError, WazuhResourceNotFound
from wazuh.core.indexer.base import BaseIndex, IndexerKey
from wazuh.core.indexer.models.rbac import Policy
from wazuh.core.indexer.utils import get_source_items

POLICY_KEY = 'policy'


class PoliciesIndex(BaseIndex):
    """Set of methods to interact with the `roles` index."""

    INDEX = 'roles'

    async def create(self, policy: Policy) -> Policy:
        """Create a new policy.

        Parameters
        ----------
        policy : Policy
            Policy instance containing its details.

        Raises
        ------
        WazuhError(4030)
            If a policy with the provided ID already exists.

        Returns
        -------
        Policy
            The created policy instance.
        """
        try:
            await self._client.index(
                index=self.INDEX, id=policy.id, body={POLICY_KEY: policy.to_dict()}, op_type='create', refresh='true'
            )
        except exceptions.ConflictError:
            raise WazuhError(4030, extra_message=policy.id)

        return policy

    async def delete(self, ids: list[str]) -> list[str]:
        """Delete multiple roles that match with the given parameters.

        Parameters
        ----------
        ids : list[str]
            Policy identifiers.

        Returns
        -------
        list[str]
            Deleted policy IDs.
        """
        body = {IndexerKey.QUERY: {IndexerKey.TERMS: {IndexerKey._ID: ids}}}
        parameters = {IndexerKey.INDEX: self.INDEX, IndexerKey.BODY: body, IndexerKey.CONFLICTS: 'proceed'}

        await self._client.delete_by_query(**parameters, refresh='true')

        return ids

    async def get(self, id: str) -> Policy:
        """Retrieve a policy.

        Parameters
        ----------
        id : str
            Policy identifier.

        Raises
        ------
        WazuhResourceNotFound(4031)
            If no roles exist with the UUID provided.

        Returns
        -------
        Policy
            Policy object.
        """
        try:
            data = await self._client.get(index=self.INDEX, id=id)
        except exceptions.NotFoundError:
            raise WazuhResourceNotFound(4031)

        return Policy(**data[IndexerKey._SOURCE][POLICY_KEY])

    async def search(
        self,
        query: dict,
        select: str | None = None,
        exclude: str | None = None,
        offset: int | None = None,
        limit: int | None = None,
        sort: str | None = None,
    ) -> list[Policy]:
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
        return [Policy(**item[POLICY_KEY]) for item in get_source_items(results)]

    async def update(self, id: str, policy: Policy) -> None:
        """Update a policy.

        Parameters
        ----------
        id : str
            Policy identifier.
        policy : Policy
            Policy fields. Only specified fields are updated.

        Raises
        ------
        WazuhResourceNotFound(4031)
            If no roles exist with the UUID provided.
        """
        try:
            body = {IndexerKey.DOC: {POLICY_KEY: policy.to_dict()}}
            await self._client.update(index=self.INDEX, id=id, body=body)
        except exceptions.NotFoundError:
            raise WazuhResourceNotFound(4031)
