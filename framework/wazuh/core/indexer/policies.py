from wazuh.core.indexer.models.rbac import Policy
from wazuh.core.indexer.rbac import RBACIndex


class PoliciesIndex(RBACIndex):
    """Set of methods to interact with the `policies` index."""

    INDEX = 'wazuh-policies'
    KEY = 'policy'

    async def create(self, policy: Policy) -> Policy:
        """Create a new policy.

        Parameters
        ----------
        policy : Policy
            Policy instance containing its details.

        Returns
        -------
        Policy
            The created policy instance.
        """
        return await super().create(policy)

    async def get(self, id: str) -> Policy:
        """Retrieve a policy.

        Parameters
        ----------
        id : str
            Policy identifier.

        Returns
        -------
        Policy
            Policy object.
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
        return await super().search(query, select, exclude, offset, limit, sort)

    async def update(self, id: str, policy: Policy) -> None:
        """Update a policy.

        Parameters
        ----------
        id : str
            Policy identifier.
        policy : Policy
            Policy fields. Only specified fields are updated.
        """
        await super().update(id, policy)
