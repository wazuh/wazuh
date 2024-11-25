from dataclasses import asdict
from unittest import mock

from opensearchpy import exceptions
import pytest

from wazuh.core.exception import WazuhError
from wazuh.core.indexer.commands import CommandsManager, STATUS_KEY, TARGET_ID_KEY, create_restart_command, \
    COMMAND_USER_NAME, create_set_group_command, create_update_group_command
from wazuh.core.indexer.base import IndexerKey, POST_METHOD
from wazuh.core.indexer.utils import convert_enums
from wazuh.core.indexer.models.commands import Action, Command, Source, Status, Target, TargetType, \
    CreateCommandResponse


class TestCommandsManager:
    index_class = CommandsManager
    create_command = Command(source=Source.ENGINE)

    @pytest.fixture
    def client_mock(self) -> mock.AsyncMock:
        return mock.AsyncMock()

    @pytest.fixture
    def index_instance(self, client_mock) -> CommandsManager:
        return self.index_class(client=client_mock)

    async def test_create(self, index_instance: CommandsManager, client_mock: mock.AsyncMock):
        """Check the correct functionality of the `create` method."""
        client_mock.transport.perform_request.return_value = {
            '_index': 'commands', '_id': 'pBjePGfvgm', 'result': 'CREATED'
        }

        response = await index_instance.create(self.create_command)

        assert isinstance(response, CreateCommandResponse)
        client_mock.transport.perform_request.assert_called_once_with(
            method=POST_METHOD,
            url=f'{index_instance.PLUGIN_URL}/commands',
            body=asdict(self.create_command, dict_factory=convert_enums),
        )
    
    async def test_create_ko(self, index_instance: CommandsManager, client_mock: mock.AsyncMock):
        """Check the error handling of the `create` method."""
        client_mock.transport.perform_request.side_effect = exceptions.RequestError(400, 'error')
        with pytest.raises(WazuhError, match='.*1761.*'):
            await index_instance.create(self.create_command)

    async def test_get(self, index_instance: CommandsManager, client_mock: mock.AsyncMock):
        """Check the correct functionality of the `get` method."""
        uuid = '0191dd54-bd16-7025-80e6-ae49bc101c7a'
        status = Status.PENDING
        query = {
            IndexerKey.QUERY: {
                IndexerKey.BOOL: {
                    IndexerKey.MUST: [
                        {IndexerKey.MATCH: {TARGET_ID_KEY: uuid}},
                        {IndexerKey.MATCH: {STATUS_KEY: status}},
                    ]
                }
            }
        }
        search_result = {IndexerKey.HITS: {IndexerKey.HITS: [
            {
                IndexerKey._ID: 'pBjePGfvgm',
                IndexerKey._SOURCE: {'target': {'id': uuid, 'type': TargetType.AGENT}, 'status': status}
            },
            {
                IndexerKey._ID: 'pBjePGfvgn',
                IndexerKey._SOURCE: {'target': {'id': '001', 'type': TargetType.AGENT}, 'status': status}
            },
        ]}}
        client_mock.search.return_value = search_result

        result = await index_instance.get(uuid=uuid, status=status)

        hits = search_result[IndexerKey.HITS][IndexerKey.HITS]
        assert result == [Command.from_dict(data[IndexerKey._ID], data[IndexerKey._SOURCE]) for data in hits]
        client_mock.search.assert_called_once_with(
            index=index_instance.INDEX,
            body=query,
        )


def test_create_restart_command():
    """Check the correct functionality of the `create_restart_command` function."""
    agent_id = '0191dd54-bd16-7025-80e6-ae49bc101c7a'
    expected_command = Command(
        source=Source.SERVICES,
        target=Target(
            type=TargetType.AGENT,
            id=agent_id,
        ),
        action=Action(
            name='restart',
            version='5.0.0'
        ),
        user=COMMAND_USER_NAME,
        timeout=100
    )

    command = create_restart_command(agent_id=agent_id)

    assert command == expected_command


def test_create_set_group_command():
    """Check the correct functionality of the `create_set_group_command` function."""
    agent_id = '0191dd54-bd16-7025-80e6-ae49bc101c7a'
    groups = ['default', 'group1', 'group3']
    expected_command = Command(
        source=Source.SERVICES,
        target=Target(
            type=TargetType.AGENT,
            id=agent_id,
        ),
        action=Action(
            name='set-group',
            args=groups,
            version='5.0.0'
        ),
        user=COMMAND_USER_NAME,
        timeout=100
    )

    command = create_set_group_command(agent_id=agent_id, groups=groups)

    assert command == expected_command


def test_create_update_group_command():
    """Check the correct functionality of the `create_update_group_command` function."""
    agent_id = '0191dd54-bd16-7025-80e6-ae49bc101c7a'
    expected_command = Command(
        source=Source.SERVICES,
        target=Target(
            type=TargetType.AGENT,
            id=agent_id,
        ),
        action=Action(
            name='update-group',
            version='5.0.0'
        ),
        user=COMMAND_USER_NAME,
        timeout=100
    )

    command = create_update_group_command(agent_id=agent_id)

    assert command == expected_command
