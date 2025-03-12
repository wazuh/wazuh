from fastapi import Request
from pydantic import BaseModel
from wazuh.core.indexer.models.commands import Command


class Commands(BaseModel):
    """Body containing a list of commands."""

    commands: list[Command]


async def post_commands(request: Request, commands: Commands) -> Commands:
    """Post commands to the API unix server.

    Parameters
    ----------
    request : Request
        Incoming HTTP request.
    commands : Commands
        Commands list.

    Returns
    -------
    Commands
        Processed commands.
    """
    processed_commands = request.app.state.commands_manager.add_commands(commands.commands)
    return Commands(commands=processed_commands)
