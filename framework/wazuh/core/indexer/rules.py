from wazuh.core.indexer.models.rbac import Rule
from wazuh.core.indexer.rbac import RBACIndex


class RulesIndex(RBACIndex):
    """Set of methods to interact with the `rules` index."""

    KEY = 'rule'
    INDEX = 'rules'

    async def create(self, rule: Rule) -> Rule:
        """Create a new rule.

        Parameters
        ----------
        rule : Rule
            Rule instance containing its details.

        Returns
        -------
        Rule
            The created rule instance.
        """
        return await super().create(rule)

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
        await super().delete(ids)
        return ids

    async def get(self, id: str) -> Rule:
        """Retrieve a rule.

        Parameters
        ----------
        id : str
            Rule identifier.

        Returns
        -------
        Rule
            Rule object.
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
        return await super().search(query, select, exclude, offset, limit, sort)

    async def update(self, id: str, rule: Rule) -> None:
        """Update a rule.

        Parameters
        ----------
        id : str
            Rule identifier.
        rule : Rule
            Rule fields. Only specified fields are updated.
        """
        await super().update(id, rule)
