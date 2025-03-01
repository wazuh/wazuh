from wazuh.core.indexer.models.rbac import Role
from wazuh.core.indexer.rbac import RBACIndex


class RolesIndex(RBACIndex):
    """Set of methods to interact with the `roles` index."""

    INDEX = 'roles'
    KEY = 'role'

    async def create(self, role: Role) -> Role:
        """Create a new role.

        Parameters
        ----------
        role : Role
            Role instance containing its details.

        Returns
        -------
        Role
            The created role instance.
        """
        return await super().create(role)

    async def get(self, id: str) -> Role:
        """Retrieve a role.

        Parameters
        ----------
        id : str
            Role identifier.

        Returns
        -------
        Role
            Role object.
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
        return await super().search(query, select, exclude, offset, limit, sort)

    async def update(self, id: str, role: Role) -> None:
        """Update a role.

        Parameters
        ----------
        id : str
            Role identifier.
        role : Role
            Role fields. Only specified fields are updated.
        """
        await super().update(id, role)
