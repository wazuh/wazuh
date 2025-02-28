from opensearchpy import exceptions
from wazuh.core.exception import WazuhError, WazuhResourceNotFound
from wazuh.core.indexer.base import BaseIndex, IndexerKey
from wazuh.core.indexer.models.rbac import Rule
from wazuh.core.indexer.utils import get_source_items

RULE_KEY = 'rule'


class RulesIndex(BaseIndex):
    """Set of methods to interact with the `rules` index."""

    INDEX = 'rules'

    async def create(self, rule: Rule) -> Rule:
        """Create a new rule.

        Parameters
        ----------
        rule : Rule
            Rule instance containing its details.

        Raises
        ------
        WazuhError(4032)
            If a rule with the provided ID already exists.

        Returns
        -------
        Rule
            The created rule instance.
        """
        try:
            await self._client.index(
                index=self.INDEX, id=rule.id, body={RULE_KEY: rule.to_dict()}, op_type='create', refresh='true'
            )
        except exceptions.ConflictError:
            raise WazuhError(4032, extra_message=rule.id)

        return rule

    async def delete(self, ids: list[str]) -> list[str]:
        """Delete multiple rules that match with the given parameters.

        Parameters
        ----------
        ids : list[str]
            Rule identifiers.

        Returns
        -------
        list[str]
            Deleted rule IDs.
        """
        body = {IndexerKey.QUERY: {IndexerKey.TERMS: {IndexerKey._ID: ids}}}
        parameters = {IndexerKey.INDEX: self.INDEX, IndexerKey.BODY: body, IndexerKey.CONFLICTS: 'proceed'}

        await self._client.delete_by_query(**parameters, refresh='true')

        return ids

    async def get(self, id: str) -> Rule:
        """Retrieve a rule.

        Parameters
        ----------
        id : str
            Rule identifier.

        Raises
        ------
        WazuhResourceNotFound(4033)
            If no rules exist with the UUID provided.

        Returns
        -------
        Rule
            Rule object.
        """
        try:
            data = await self._client.get(index=self.INDEX, id=id)
        except exceptions.NotFoundError:
            raise WazuhResourceNotFound(4033)

        return Rule(**data[IndexerKey._SOURCE][RULE_KEY])

    async def search(
        self,
        query: dict,
        select: str | None = None,
        exclude: str | None = None,
        offset: int | None = None,
        limit: int | None = None,
        sort: str | None = None,
    ) -> list[Rule]:
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
        return [Rule(**item[RULE_KEY]) for item in get_source_items(results)]

    async def update(self, id: str, rule: Rule) -> None:
        """Update a rule.

        Parameters
        ----------
        id : str
            Rule identifier.
        rule : Rule
            Rule fields. Only specified fields are updated.

        Raises
        ------
        WazuhResourceNotFound(4033)
            If no rules exist with the UUID provided.
        """
        try:
            body = {IndexerKey.DOC: {RULE_KEY: rule.to_dict()}}
            await self._client.update(index=self.INDEX, id=id, body=body)
        except exceptions.NotFoundError:
            raise WazuhResourceNotFound(4033)
