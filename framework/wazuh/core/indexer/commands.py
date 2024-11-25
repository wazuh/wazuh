from dataclasses import asdict
from typing import List, Optional, Union

from opensearchpy import exceptions
from uuid6 import UUID

from .base import BaseIndex, IndexerKey, remove_empty_values, POST_METHOD
from .utils import convert_enums
from wazuh.core.exception import WazuhError, WazuhResourceNotFound
from wazuh.core.indexer.models.commands import Action, Command, Result, Source, Status, Target, TargetType, \
    CreateCommandResponse, ResponseResult
 
DOC_ID_KEY = 'id'
TARGET_ID_KEY = 'target.id'
STATUS_KEY = 'status'
COMMAND_USER_NAME = 'Management API'


class CommandsManager(BaseIndex):
    """Set of methods to interact with the commands manager."""

    INDEX = '.commands'
    PLUGIN_URL = '/_plugins/_command_manager'

    async def create(self, command: Command) -> CreateCommandResponse:
        """Create a new command.
        
        Parameters
        ----------
        command : Command
            New command.
        
        Returns
        -------
        CreateCommandResponse
            Indexer command manager response.
        """
        try:
            response = await self._client.transport.perform_request(
                method=POST_METHOD,
                url=f'{self.PLUGIN_URL}/commands',
                body=asdict(command, dict_factory=convert_enums),
            )
        except exceptions.RequestError as e:
            raise WazuhError(1761, extra_message=str(e))

        return CreateCommandResponse(
            index=response.get(IndexerKey._INDEX),
            document_id=response.get(IndexerKey._ID),
            result=ResponseResult(response.get(IndexerKey.RESULT)),
        )

    async def get(self, uuid: UUID, status: Status) -> Optional[List[Command]]:
        """Get commands with the provided status from an specific agent.

        Parameters
        ----------
        uuid : UUID
            Agent universally unique identifier.
        status: Status
            Command execution status.

        Returns
        -------
        Optional[ListCommand]
            Commands list or None.
        """
        body = {
            IndexerKey.QUERY: {
                IndexerKey.BOOL: {
                    IndexerKey.MUST: [
                        {IndexerKey.MATCH: {TARGET_ID_KEY: uuid}},
                        {IndexerKey.MATCH: {STATUS_KEY: status}},
                    ]
                }
            }
        }

        response = await self._client.search(index=self.INDEX, body=body)
        hits = response[IndexerKey.HITS][IndexerKey.HITS]
        if len(hits) == 0:
            return None

        commands = []
        for data in hits:
            commands.append(Command.from_dict(data[IndexerKey._ID], data[IndexerKey._SOURCE]))

        return commands

    async def update(self, items: List[Union[Command, Result]]) -> None:
        """Update commands.
        
        Parameters
        ----------
        items : List[Union[Command, Result]]
            List of commands or results to update.

        Raises
        ------
        WazuhResourceNotFound(2202)
            If no document exists with the id provided.
        """
        actions = []
        for item in items:
            actions.append({IndexerKey.UPDATE: {IndexerKey._INDEX: self.INDEX, IndexerKey._ID: item.id}})
            item_dict = asdict(item, dict_factory=remove_empty_values)
            # The document ID shouldn't be part of the value
            item_dict.pop(DOC_ID_KEY, None)
            actions.append({IndexerKey.DOC: item_dict})

        # TODO(25121): Create an internal library to build opensearch requests and parse responses
        response = await self._client.bulk(actions, self.INDEX)
        for item in response[IndexerKey.ITEMS]:
            if item[IndexerKey.UPDATE][STATUS_KEY] == 404:
                raise WazuhResourceNotFound(2202)


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
