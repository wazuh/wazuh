import asyncio
import pytest
from uvloop import EventLoopPolicy, Loop

@pytest.fixture(scope="session")
def event_loop() -> Loop:
    asyncio.set_event_loop_policy(EventLoopPolicy())
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()