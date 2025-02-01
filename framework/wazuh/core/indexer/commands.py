from dataclasses import asdict
from typing import List

from opensearchpy import exceptions
from opensearchpy._async.helpers.search import AsyncSearch
from opensearchpy._async.helpers.update_by_query import AsyncUpdateByQuery


from .base import BaseIndex, IndexerKey, POST_METHOD
from .utils import convert_enums
from wazuh.core.exception import WazuhError
from wazuh.core.indexer.models.commands import (
    Action, Command, Source, Status, Target, TargetType, CreateCommandResponse, ResponseResult
)

COMMAND_USER_NAME = 'Management API'
COMMAND_KEY = 'command'


class CommandsManager(BaseIndex):
    """Set of methods to interact with the commands manager."""

    INDEX = 'wazuh-commands'
    PLUGIN_URL = '/_plugins/_command_manager'

    UPDATE_STATUS_SCRIPT = 'ctx._source.command.status = new String[] {params.status};'

    async def create(self, commands: List[Command]) -> CreateCommandResponse:
        """Create a new command.

        Parameters
        ----------
        commands : List[Command]
            New commands list.

        Returns
        -------
        CreateCommandResponse
            Indexer command manager response.
        """
        commands_to_send = []
        for command in commands:
            command_body = asdict(command, dict_factory=convert_enums)
            commands_to_send.append(command_body)

        try:
            response = await self._client.transport.perform_request(
                method=POST_METHOD,
                url=f'{self.PLUGIN_URL}/commands',
                body={'commands': commands_to_send},
            )
        except (exceptions.RequestError, exceptions.TransportError) as e:
            raise WazuhError(1761, extra_message=str(e))

        document_ids = []
        for document in response.get(IndexerKey._DOCUMENTS):
            document_ids.append(document.get(IndexerKey._ID))

        return CreateCommandResponse(
            index=response.get(IndexerKey._INDEX),
            document_ids=document_ids,
            result=ResponseResult(response.get(IndexerKey.RESULT)),
        )

    async def get_commands(self, status: Status) -> List[Command]:
        """Get commands that match with the given parameters.

        Parameters
        ----------
        status : Status
            Status name.

        Returns
        -------
        commands : List[Command]
            Command list.
        """
        query = AsyncSearch(using=self._client, index=self.INDEX).filter({
            IndexerKey.TERM: {
                f'{COMMAND_KEY}.{IndexerKey.STATUS}': status.value
            }
        })
        response = await query.execute()

        commands = []
        for hit in response:
            commands.append(Command(
                document_id=hit.meta[IndexerKey.ID],
                **hit.to_dict()[COMMAND_KEY]
            ))

        return commands

    async def update_commands_status(self, order_ids: List[str], status: str):
        """Update the status for a list of order id's

        Args:
            order_ids (List[str]): List of order id's to update.
            status (str): New status to set.
        """
        query = AsyncUpdateByQuery(using=self._client, index=self.INDEX).filter(
            {
                IndexerKey.TERMS: {'command.order_id': order_ids}
            }
        ).script(
            source=self.UPDATE_STATUS_SCRIPT,
            lang=IndexerKey.PAINLESS,
            params={'status': status}
        )
        _ = await query.execute()


def create_restart_command(agent_id: str) -> Command:
    """Create a restart command for an agent with the ID specified.

    Parameters
    ----------
    agent_id : str
        Agent ID.

    Returns
    -------
    Command
        Restart command.
    """
    # The restart command hasn't been designed yet, this is a sample value.
    # To be defined in https://github.com/wazuh/wazuh-agent/issues/54.
    return Command(
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
        timeout=100,
    )


def create_set_group_command(agent_id: str, groups: List[str]) -> Command:
    """Create a set group command for an agent with the ID specified.

    Parameters
    ----------
    agent_id : str
        Agent ID.
    groups : List[str]
        Group names list.

    Returns
    -------
    Command
        Set group command.
    """
    return Command(
        source=Source.SERVICES,
        target=Target(
            type=TargetType.AGENT,
            id=agent_id,
        ),
        action=Action(
            name='set-group',
            args={
                'groups': groups
            },
            version='5.0.0'
        ),
        user=COMMAND_USER_NAME,
        timeout=100,
    )


def create_fetch_config_command(agent_id: str) -> Command:
    """Create a fetch config command for an agent with the ID specified.

    Parameters
    ----------
    agent_id : str
        Agent ID.

    Returns
    -------
    Command
        Fetch config command.
    """
    return Command(
        source=Source.SERVICES,
        target=Target(
            type=TargetType.AGENT,
            id=agent_id,
        ),
        action=Action(
            name='fetch-config',
            args={},
            version='5.0.0'
        ),
        user=COMMAND_USER_NAME,
        timeout=100,
    )
