from wazuh.core.indexer import get_indexer_client
from wazuh.core.indexer.base import IndexerKey
from wazuh.core.indexer.models.policy import Policy
from wazuh.core.indexer.models.role import Role
from wazuh.core.indexer.models.rule import Rule
from wazuh.core.indexer.models.user import User

MATCH_ALL_QUERY = {IndexerKey.MATCH_ALL: {}}


async def get_policies() -> list[Policy]:
    """Get all RBAC policies."""
    async with get_indexer_client() as indexer_client:
        return indexer_client.policies.search(query=MATCH_ALL_QUERY)


async def get_roles() -> list[Role]:
    """Get all RBAC roles."""
    async with get_indexer_client() as indexer_client:
        return indexer_client.roles.search(query=MATCH_ALL_QUERY)


async def get_rules() -> list[Rule]:
    """Get all RBAC rules."""
    async with get_indexer_client() as indexer_client:
        return indexer_client.rules.search(query=MATCH_ALL_QUERY)


async def get_users() -> list[User]:
    """Get all RBAC users."""
    async with get_indexer_client() as indexer_client:
        return indexer_client.roles.search(query=MATCH_ALL_QUERY)
