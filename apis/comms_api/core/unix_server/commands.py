from fastapi import Request

from comms_api.models.commands import Commands


async def post_commands(request: Request, commands: Commands) -> Commands:
    """Post commands to the Communications API.

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
