from dataclasses import asdict
from unittest import mock

import pytest
from wazuh.core.indexer.commands import CommandsIndex
from wazuh.core.indexer.base import POST_METHOD, remove_empty_values
from wazuh.core.indexer.models.commands import Command, Source, CreateCommandResponse


class TestCommandsIndex:
    index_class = CommandsIndex
    create_command = Command(source=Source.ENGINE, user='0191480e-7f67-7fd3-8c52-f49a3176360b')

    @pytest.fixture
    def client_mock(self) -> mock.AsyncMock:
        return mock.AsyncMock()

    @pytest.fixture
    def index_instance(self, client_mock) -> CommandsIndex:
        return self.index_class(client=client_mock)

    async def test_create(self, index_instance: CommandsIndex, client_mock: mock.AsyncMock):
        """Check the correct function of `create` method."""
        response = await index_instance.create(self.create_command)

        assert isinstance(response, CreateCommandResponse)
        client_mock.transport.perform_request.assert_called_once_with(
            method=POST_METHOD,
            url=index_instance.COMMAND_MANAGER_PLUGIN_URL,
            body=asdict(self.create_command, dict_factory=remove_empty_values),
        )
