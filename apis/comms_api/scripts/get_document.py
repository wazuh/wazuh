import asyncio
from wazuh.core.indexer import get_indexer_client

DOCUMENT_QUERY = {
    "query": {
        "ids": {
            "values": ["0AfAjJEBL2-AxgFlyXyB"]
        }
    }
}

MATCH_ALL_QUERY = {
    "query": {
        "match_all": {}
    }
}

async def main():
    try:
        async with get_indexer_client() as indexer_client:
            # Perform the asynchronous operation
            query = MATCH_ALL_QUERY
            response = await indexer_client._client.search(
                index="events",
                body=query,
                size=1000
            )
            hits = response['hits']['hits']
            for hit in hits:
                # Process the document
                print(hit['_source'])
            print(f"Number of elements {len(hits)}")
    except Exception as e:
        print(f"An error occurred: {e}")

# Run the main function
if __name__ == "__main__":
    asyncio.run(main())