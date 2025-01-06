from dataclasses import asdict
from typing import List, Optional

from opensearchpy import exceptions
from opensearchpy._async.helpers.search import AsyncSearch

from .base import BaseIndex, IndexerKey, POST_METHOD
from .utils import convert_enums, get_source_items
from wazuh.core.exception import WazuhError
from wazuh.core.indexer.models.commands import (
    Action, Command, Source, Target, TargetType, CreateCommandResponse, ResponseResult
)

COMMAND_USER_NAME = 'Management API'
COMMAND_KEY = 'command'


class CommandsIndex(BaseIndex):
    INDEX = '.commands'

    async def search(
        self,
        query: dict,
        offset: Optional[int] = None,
        limit: Optional[int] = None,
    ) -> List[Command]:
        """Perform a search operation with the given query.

        Parameters
        ----------
        query : dict
            DSL query.
        select : Optional[str], optional
            A comma-separated list of fields to include in the response, by default None.
        exclude : Optional[str], optional
            A comma-separated list of fields to exclude from the response, by default None.
        offset : Optional[int], optional
            The starting index to search from, by default None.
        limit : Optional[int], optional
            How many results to include in the response, by default None.
        sort : Optional[str], optional
            A comma-separated list of fields to sort by, by default None.

        Returns
        -------
        dict
            The search result.
        """
        parameters = {IndexerKey.INDEX: self.INDEX, IndexerKey.BODY: query}
        results = await self._client.search(**parameters, size=limit, from_=offset)
        return [Command(**item['command']) for item in get_source_items(results)]


class CommandsManager(BaseIndex):
    """Set of methods to interact with the commands manager."""

    INDEX = '.commands'
    PLUGIN_URL = '/_plugins/_command_manager'

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

    async def get_commands(self, status: str) -> List[Command]:
        """Get commands that match with the given parameters.

        Parameters
        ----------
        status : str
            Status name.

        Returns
        -------
        commands : List[Command]
            Command list.
        """
        query = AsyncSearch(using=self._client, index=self.INDEX).filter({
            IndexerKey.TERM: {
                f'{COMMAND_KEY}.{IndexerKey.STATUS}': status
            }
        })
        response = await query.execute()

        commands = []
        for hit in response:
            commands.append(Command(**hit.to_dict()[COMMAND_KEY]))

        return commands


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
            args=groups,
            version='5.0.0'
        ),
        user=COMMAND_USER_NAME,
        timeout=100,
    )


def create_update_group_command(agent_id: str) -> Command:
    """Create a update group command for an agent with the ID specified.

    Parameters
    ----------
    agent_id : str
        Agent ID.

    Returns
    -------
    Command
        Update group command.
    """
    return Command(
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
        timeout=100,
    )
