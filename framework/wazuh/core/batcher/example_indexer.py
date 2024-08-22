import asyncio
import os

from wazuh.core.indexer import create_indexer
from wazuh.core.indexer.bulk import BulkDoc

INDEXER_HOST = os.environ.get('WAZUH_INDEXER_HOST', '127.0.0.1')
INDEXER_PORT = os.environ.get('WAZUH_INDEXER_PORT', 9200)
INDEXER_USER = os.environ.get('WAZUH_INDEXER_USER', 'admin')
INDEXER_PASSWORD = os.environ.get('WAZUH_INDEXER_PASSWORD', 'SecretPassword1%')

INDEXER_INDEX_NAME = "example-events"


async def main():
    client = await create_indexer(host=INDEXER_HOST, user=INDEXER_USER, password=INDEXER_PASSWORD, use_ssl=False)
    list_of_events = []
    for i in range(10):
        list_of_events.append(BulkDoc.create(index=INDEXER_INDEX_NAME, doc_id=str(i), doc={'text': f'Example with id {i}'}))

    print("Bulk operation result\n")
    response = await client.events.bulk(list_of_events)
    print(response)

    await client.close()


if __name__ == '__main__':
    asyncio.run(main())