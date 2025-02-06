from fastapi import status
from wazuh.core.exception import WazuhIndexerError, WazuhInternalError, WazuhResourceNotFound
from wazuh.core.indexer import get_indexer_client
from wazuh.core.indexer.models.agent import Agent, Status
from wazuh.core.utils import get_utc_now

from comms_api.authentication.authentication import generate_token
from comms_api.models.authentication import Credentials, TokenResponse
from comms_api.routers.exceptions import HTTPError
from comms_api.routers.utils import timeout


@timeout(20)
async def authentication(credentials: Credentials) -> TokenResponse:
    """Authentication endpoint handler.

    Parameters
    ----------
    credentials : Credentials
        Agent credentials.

    Raises
    ------
    HTTPError
        If there is an error during the authentication.

    Returns
    -------
    TokenResponse
        JWT token.
    """
    try:
        async with get_indexer_client() as indexer_client:
            agent = await indexer_client.agents.get(credentials.uuid)

            if not agent.check_key(credentials.key):
                raise HTTPError(message='Invalid key', status_code=status.HTTP_401_UNAUTHORIZED)

            token = generate_token(credentials.uuid)

            body = Agent(last_login=get_utc_now(), status=Status.ACTIVE)
            await indexer_client.agents.update(credentials.uuid, body)
    except WazuhIndexerError as exc:
        raise HTTPError(message=f'Couldn\'t connect to the indexer: {str(exc)}', status_code=status.HTTP_403_FORBIDDEN)
    except WazuhResourceNotFound:
        raise HTTPError(message='Agent does not exist', status_code=status.HTTP_403_FORBIDDEN)
    except WazuhInternalError as exc:
        raise HTTPError(message=f'Couldn\'t get key pair: {str(exc)}', status_code=status.HTTP_403_FORBIDDEN)

    return TokenResponse(token=token)
