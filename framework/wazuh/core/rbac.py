from wazuh.core.indexer import get_indexer_client
from wazuh.core.indexer.base import IndexerKey
from wazuh.core.indexer.models.rbac import User

MATCH_ALL_QUERY = {IndexerKey.MATCH_ALL: {}}


async def get_users() -> list[User]:
    """Get all RBAC users."""
    async with get_indexer_client() as indexer_client:
        return indexer_client.users.search(query=MATCH_ALL_QUERY)
