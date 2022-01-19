# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from copy import copy
from datetime import datetime
from unittest.mock import AsyncMock, patch
from freezegun import freeze_time
import pytest

from api.middlewares import set_user_name, unlock_ip, _cleanup_detail_field, prevent_bruteforce_attack, \
    prevent_denial_of_service, security_middleware
from wazuh.core.exception import WazuhPermissionError, WazuhTooManyRequests


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


def test_cleanup_detail_field():
    """Test `_cleanup_detail_field` function."""
    detail = """Testing

    Details field.
    """

    assert _cleanup_detail_field(detail) == "Testing. Details field."


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
@freeze_time(datetime(1970, 1, 1, 0, 0, 10))
@pytest.mark.asyncio
async def test_middlewares_unlock_ip():
    from api.middlewares import ip_stats, ip_block
    # Assert they are not empty
    assert ip_stats and ip_block
    await unlock_ip(DummyRequest({'remote': "ip"}), 5)
    # Assert that under these conditions, they have been emptied
    assert not ip_stats and not ip_block


@patch("api.middlewares.ip_stats", new={"ip": {'timestamp': 5}})
@patch("api.middlewares.ip_block", new={"ip"})
@freeze_time(datetime(1970, 1, 1))
@pytest.mark.asyncio
async def test_middlewares_unlock_ip_ko():
    """Test if `unlock_ip` raises an exception if the IP is still blocked."""
    with patch("api.middlewares.raise_if_exc") as raise_mock:
        await unlock_ip(DummyRequest({'remote': "ip"}), 5)
        raise_mock.assert_called_once_with(WazuhPermissionError(6000))


@pytest.mark.parametrize("stats", [
    {},
    {'ip': {'attempts': 4}},
])
@pytest.mark.asyncio
async def test_middlewares_prevent_bruteforce_attack(stats):
    """Test `prevent_bruteforce_attack` blocks IPs when reaching max number of attempts."""
    request = {'path': '/security/user/authenticate', 'method': 'GET', 'remote': 'ip'}
    with patch("api.middlewares.ip_stats", new=copy(stats)):
        from api.middlewares import ip_stats, ip_block
        previous_attempts = ip_stats['ip']['attempts'] if 'ip' in ip_stats else 0
        await prevent_bruteforce_attack(DummyRequest(request),
                                        attempts=5)
        if stats:
            # There were previous attempts. This one reached the limit
            assert ip_stats['ip']['attempts'] == previous_attempts + 1
            assert 'ip' in ip_block
        else:
            # There were not previous attempts
            assert ip_stats['ip']['attempts'] == 1
            assert 'ip' not in ip_block


@freeze_time(datetime(1970, 1, 1))
@pytest.mark.parametrize("current_time, max_requests", [
    (-80, 300),
    (0, 0),
])
@pytest.mark.asyncio
async def test_middlewares_prevent_denial_of_service(current_time, max_requests):
    """Test if the DOS mechanism triggers when the `max_requests` are reached."""
    with patch("api.middlewares.current_time", new=current_time):
        with patch("api.middlewares.raise_if_exc") as raise_mock:
            await prevent_denial_of_service(DummyRequest({'remote': 'ip'}), max_requests=max_requests)
            if max_requests == 0:
                raise_mock.assert_called_once_with(WazuhTooManyRequests(6001))


@patch("api.middlewares.unlock_ip")
@patch("api.middlewares.prevent_denial_of_service")
@pytest.mark.asyncio
async def test_middlewares_security_middleware(denial_mock, unlock_mock):
    """Test that all security middlewares are correctly set following the API configuration."""
    max_req = 5
    block_time = 10
    request = DummyRequest({})

    with patch("api.middlewares.api_conf", new={'access': {'max_request_per_minute': max_req,
                                                           'block_time': block_time}}):
        await security_middleware(request, handler_mock)

        denial_mock.assert_called_once_with(request, max_requests=max_req)
        unlock_mock.assert_called_once_with(request, block_time=block_time)
