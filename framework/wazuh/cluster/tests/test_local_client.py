# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import patch
from wazuh.exception import WazuhException
from wazuh.cluster.local_client import LocalClient
import pytest
import asyncio
import uvloop

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
loop = uvloop.new_event_loop()

@patch.object(loop, attribute='create_unix_connection', side_effect=MemoryError)
@patch('asyncio.get_running_loop', return_value=loop)
def test_crypto(mock_runningloop, mock_loop):
    with pytest.raises(WazuhException, match=".* 1119 .*"):
        local_client = LocalClient(b'send_file', "{} {}".format('/var/ossec', None).encode(), False)
        loop.run_until_complete(local_client.start())
