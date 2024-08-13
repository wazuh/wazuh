import asyncio
import os

from wazuh.core.indexer import create_indexer

INDEXER_HOST = os.environ.get('WAZUH_INDEXER_HOST', '127.0.0.1')
INDEXER_PORT = os.environ.get('WAZUH_INDEXER_PORT', 9200)
INDEXER_USER = os.environ.get('WAZUH_INDEXER_USER', 'admin')
INDEXER_PASSWORD = os.environ.get('WAZUH_INDEXER_PASSWORD', 'SecretPassword1%')

INDEXER_INDEX_NAME = "events"


async def main():
    client = await create_indexer(host=INDEXER_HOST, user=INDEXER_USER, password=INDEXER_PASSWORD, use_ssl=False)
    response = await client._client.indices.create(INDEXER_INDEX_NAME)
    print(response)

    await client.close()


if __name__ == '__main__':
    asyncio.run(main())