from unittest.mock import MagicMock, patch

import pytest
from fastapi import status

from comms_api.routers.events import post_stateful_events, post_stateless_events
from comms_api.routers.exceptions import HTTPError
from wazuh.core.exception import WazuhEngineError, WazuhError


@pytest.mark.asyncio
@patch('comms_api.routers.events.create_stateful_events', return_value={'foo': 'bar'})
async def test_post_stateful_events(post_stateful_events_mock):
    """Verify that the `post_stateful_events` handler works as expected."""
    events = []
    response = await post_stateful_events(events)

    post_stateful_events_mock.assert_called_once_with(events)
    assert response.status_code == status.HTTP_200_OK
    assert response.body == b'{"foo":"bar"}'


@pytest.mark.asyncio
async def test_post_stateful_events_ko():
    """Verify that the `post_stateful_events` handler catches exceptions successfully."""
    code = status.HTTP_400_BAD_REQUEST
    exception = WazuhError(2200)

    with patch('comms_api.routers.events.create_stateful_events', MagicMock(side_effect=exception)):
        with pytest.raises(HTTPError, match=fr'{code}: {exception.message}'):
            _ = await post_stateful_events('')


@pytest.mark.asyncio
@patch('comms_api.routers.events.send_stateless_events')
async def test_post_stateless_events(send_stateless_events_mock):
    """Verify that the `post_stateless_events` handler works as expected."""
    events = []
    response = await post_stateless_events(events)

    send_stateless_events_mock.assert_called_once_with(events)
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
async def test_post_stateless_events_ko():
    """Verify that the `post_stateless_events` handler catches exceptions successfully."""
    exception = WazuhEngineError(2802)

    with patch('comms_api.routers.events.send_stateless_events', MagicMock(side_effect=exception)):
        with pytest.raises(HTTPError, match=fr'{exception.code}: {exception.message}'):
            _ = await post_stateless_events('')
