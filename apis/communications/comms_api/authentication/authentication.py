from typing import Optional

from fastapi import Request, status
from fastapi.exceptions import HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import decode, encode
from jwt.exceptions import PyJWTError
from wazuh.core.authentication import JWT_ALGORITHM, JWT_ISSUER, get_keypair
from wazuh.core.exception import WazuhCommsAPIError
from wazuh.core.utils import get_utc_now

from comms_api.routers.exceptions import HTTPError

JWT_AUDIENCE = 'Wazuh Communications API'
JWT_EXPIRATION = 900


class JWTBearer(HTTPBearer):
    def __init__(self):
        super(JWTBearer, self).__init__(auto_error=True)

    async def __call__(self, request: Request) -> str:
        """Get JWT token from the request header and validate it.

        Parameters
        ----------
        request : Request
            HTTP request.

        Raises
        ------
        HTTPError
            Invalid token error.

        Returns
        -------
        str
            HTTP Authorization header credentials.
        """
        try:
            credentials: Optional[HTTPAuthorizationCredentials] = await super(JWTBearer, self).__call__(request)
            payload = decode_token(credentials.credentials)
            # Store the agent UUID in the request context
            request.state.agent_uuid = payload.get('uuid', '')
        except HTTPException as exc:
            raise HTTPError(message=str(exc), status_code=status.HTTP_403_FORBIDDEN)
        except WazuhCommsAPIError as exc:
            raise HTTPError(message=exc.message, code=exc.code, status_code=status.HTTP_403_FORBIDDEN)
        except Exception as exc:
            raise HTTPError(message=str(exc), status_code=status.HTTP_403_FORBIDDEN)

        return credentials.credentials


def decode_token(token: str) -> dict:
    """Decode a JWT formatted token.

    Parameters
    ----------
    token : str
        Encoded JWT token.

    Raises
    ------
    Exception
        If the token validation fails.

    Returns
    -------
    dict
        Dictionary with the token payload.
    """
    try:
        _, public_key = get_keypair()
        payload = decode(token, public_key, algorithms=[JWT_ALGORITHM], audience=JWT_AUDIENCE)

        if (payload['exp'] - payload['iat']) != JWT_EXPIRATION:
            raise WazuhCommsAPIError(2706)

        current_timestamp = int(get_utc_now().timestamp())
        if payload['exp'] <= current_timestamp:
            raise WazuhCommsAPIError(2707)

        return payload
    except PyJWTError as exc:
        raise WazuhCommsAPIError(2706) from exc


def generate_token(uuid: str) -> str:
    """Generate an encoded JWT token.

    Parameters
    ----------
    uuid : str
        Unique agent identifier.

    Returns
    -------
    str
        Encoded JWT token.
    """
    timestamp = int(get_utc_now().timestamp())
    payload = {
        'iss': JWT_ISSUER,
        'aud': JWT_AUDIENCE,
        'iat': timestamp,
        'exp': timestamp + JWT_EXPIRATION,
        'uuid': uuid,
    }
    private_key, _ = get_keypair()

    return encode(payload, private_key, algorithm=JWT_ALGORITHM)
