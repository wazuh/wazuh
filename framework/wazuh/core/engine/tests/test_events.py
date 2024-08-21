from unittest import mock

import pytest

from wazuh.core.engine.events import EventsModule
from wazuh.core.engine.models.events import StatelessEvent


class TestEventsModule:
    module_class = EventsModule

    @pytest.fixture
    def client_mock(self) -> mock.AsyncMock:
        return mock.AsyncMock()

    @pytest.fixture
    def module_instance(self, client_mock) -> EventsModule:
        return self.module_class(client=client_mock)

    async def test_send(self, module_instance: EventsModule):
        """Check that the EventsModule `send` method works as expected."""
        events = [StatelessEvent(data='data')]
        await module_instance.send(events)
