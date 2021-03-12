# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import asyncio
from unittest.mock import patch

import pytest
import uvloop

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        from wazuh.core.exception import WazuhException
        from wazuh.core.cluster.local_client import LocalClient

asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
loop = uvloop.new_event_loop()


@patch.object(loop, attribute='create_unix_connection', side_effect=MemoryError)
@patch('asyncio.get_running_loop', return_value=loop)
def test_crypto(mock_runningloop, mock_loop):
    with pytest.raises(WazuhException, match=".* 1119 .*"):
        local_client = LocalClient()
        loop.run_until_complete(local_client.start())
