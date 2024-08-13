from unittest.mock import MagicMock, patch

import pytest
from fastapi import status

from comms_api.routers.events import stateful_events
from comms_api.routers.exceptions import HTTPError
from wazuh.core.exception import WazuhError


@pytest.mark.asyncio
@patch('comms_api.routers.events.post_stateful_events', return_value={'foo': 'bar'})
async def test_stateful_events(post_stateful_events_mock):
    """Verify that the `stateful_events` handler works as expected."""
    events = ['test']
    response = await stateful_events(events)

    post_stateful_events_mock.assert_called_once_with(events)
    assert response.status_code == status.HTTP_200_OK
    assert response.body == b'{"foo":"bar"}'


@pytest.mark.asyncio
async def test_stateful_events_ko():
    """Verify that the `stateful_events` handler catches exceptions successfully."""
    code = status.HTTP_400_BAD_REQUEST
    exception = WazuhError(2200)

    with patch('comms_api.routers.events.post_stateful_events', MagicMock(side_effect=exception)):
        with pytest.raises(HTTPError) as exc:
            _ = await stateful_events('')

    assert str(exc.value) == f'{code}: {exception.message}'
