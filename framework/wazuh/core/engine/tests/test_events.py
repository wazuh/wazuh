from unittest import mock

import pytest

from wazuh.core.engine.events import EventsModule
from wazuh.core.engine.models.events import StatelessEvent, WazuhLocation, Event


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
        response.status_code = 200
        client_mock.post.return_value = response

        events = [StatelessEvent(wazuh=WazuhLocation(queue=50, location="[003] (agent-name) any->/tmp/syslog.log"),
                                 event=Event(original="original message, recollected from the agent"))]
        await module_instance.send(events)
