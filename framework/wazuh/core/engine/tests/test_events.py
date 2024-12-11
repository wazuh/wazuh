from unittest import mock

import pytest

from wazuh.core.engine.events import EventsModule
from wazuh.core.exception import WazuhError


class TestEventsModule:
    module_class = EventsModule

    @pytest.fixture
    def client_mock(self) -> mock.AsyncMock:
        return mock.AsyncMock()

    @pytest.fixture
    def module_instance(self, client_mock) -> EventsModule:
        return self.module_class(client=client_mock)

    async def test_send(self, client_mock, module_instance: EventsModule):
        """Check that the EventsModule `send` method works as expected."""
        response = mock.MagicMock()
        response.is_error = False
        client_mock.post.return_value = response

        await module_instance.send(b'')
    
    async def test_send_ko(self, client_mock, module_instance: EventsModule):
        """Check that the EventsModule `send` handles exceptions successfully."""
        response = mock.MagicMock()
        response.is_error = True
        response.json = mock.MagicMock()
        response.json.return_value={'error': ['Service Unavailable', 'failure'], 'code': 400}
        client_mock.post.return_value = response

        expected_error_msg = 'Error 2710 - Invalid stateless events request: Service Unavailable: failure'
        with pytest.raises(WazuhError, match=expected_error_msg):
            await module_instance.send(b'')
