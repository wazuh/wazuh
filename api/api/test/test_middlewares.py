# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

from unittest.mock import AsyncMock, patch

import pytest

from api.middlewares import set_user_name, unlock_ip, _cleanup_detail_field
from wazuh.core.exception import WazuhPermissionError


class DummyRequest:
    def __init__(self, data: dict):
        self.data = data

        # Set properties
        for k, v in data.items():
            setattr(self, k, v)

    def __contains__(self, item):
        return item in self.data

    def __getitem__(self, key):
        return self.data[key]

    def __setitem__(self, key, value):
        self.data[key] = value

    def json(self):
        return self.data


handler_mock = AsyncMock()


@pytest.mark.parametrize("req", [
    DummyRequest({'token_info': {'sub': 'test'},
                  'user': None}),
    DummyRequest({'user': None}),
])
@pytest.mark.asyncio
async def test_middlewares_set_user_name(req):
    """Test `set_user_name` updates user when there is `token_info`."""
    await set_user_name(req, handler_mock)
    processed_request = handler_mock.call_args.args[-1]

    assert processed_request['user'] if "token_info" in req else processed_request['user'] is None


@patch("api.middlewares.ip_stats", new={'ip': {'timestamp': 5}})
@patch("api.middlewares.ip_block", new={"ip"})
@patch("api.middlewares.time", return_value=10)
@pytest.mark.asyncio
async def test_middlewares_unlock_ip(time_mock):
    from api.middlewares import ip_stats, ip_block
    # Assert they are not empty
    assert ip_stats and ip_block
    await unlock_ip(DummyRequest({'remote': "ip"}), 5)
    # Assert that under these conditions, they have been emptied
    assert not ip_stats and not ip_block


@patch("api.middlewares.ip_stats", new={"ip": {'timestamp': 5}})
@patch("api.middlewares.ip_block", new={"ip"})
@patch("api.middlewares.time", return_value=0)
@pytest.mark.asyncio
async def test_middlewares_unlock_ip_ko(time_mock):
    """Test if `unlock_ip` raises an exception if the IP is still blocked."""
    with patch("api.middlewares.raise_if_exc") as raise_mock:
        await unlock_ip(DummyRequest({'remote': "ip"}), 5)
        raise_mock.assert_called_once_with(WazuhPermissionError(6000))


def test_cleanup_detail_field():
    """Test `_cleanup_detail_field` function."""
    detail = """Testing.
    
    Details field.
    """

    assert _cleanup_detail_field(detail) == "Testing. Details field."
