import asyncio
from wazuh.core.indexer import get_indexer_client

async def main():
    try:
        async with get_indexer_client() as indexer_client:
            # Perform the asynchronous operation
            await indexer_client.agents.create(id='01912d07-b9b4-7528-bdad-15da902d651c', key='testing', name='test')
            print("Agent created successfully.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Run the main function
if __name__ == "__main__":
    asyncio.run(main())