from fastapi import Request, Response

from comms_api.models.commands import Commands


async def post_commands(request: Request, commands: Commands) -> Response:
    """Post commands to the Communications API.
    
    Parameters
    ----------
    request : Request
        Incoming HTTP request.
    commands : Commands
        Commands list.
    
    Returns
    -------
    Response
        HTTP OK empty response.
    """
    request.app.state.commands_manager.add_commands(commands.commands)
    return Response()
