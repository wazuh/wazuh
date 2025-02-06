# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2


import asyncio

import pytest
from uvloop import EventLoopPolicy, Loop


@pytest.fixture(scope='session')
def event_loop() -> Loop:
    asyncio.set_event_loop_policy(EventLoopPolicy())
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()
