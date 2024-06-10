from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from datetime import datetime, timezone
from fastapi import Request, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
import os


JWT_ISSUER = "wazuh"
JWT_AUDIENCE = "Wazuh Agent Comms API"
JWT_ALGORITHM = "ES256"
JWT_EXPIRATION = 900
_private_key_path = "private_key.pem"
_public_key_path = "public_key.pem"
EXPIRED_TOKEN = "Token expired"
INVALID_TOKEN = "Invalid token"

class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True, check_send_commands: bool = False):
        self.check_send_commands = check_send_commands
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials: HTTPAuthorizationCredentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(status_code=403, detail="Invalid authentication scheme.")

            try:
                self.validate_token(credentials.credentials)
            except Exception as e:
                raise HTTPException(status_code=403, detail=str(e))

            return credentials.credentials
        else:
            raise HTTPException(status_code=403, detail="Invalid authorization code.")

    def validate_token(self, token: str) -> None:
        payload = decode_token(token)

        if self.check_send_commands and not payload["can_send_commands"]:
            raise Exception("Agents are not allowed to send commands")

        if (payload["exp"] - payload["iat"]) != JWT_EXPIRATION:
            raise Exception(INVALID_TOKEN)

        current_timestamp = int(datetime.utcnow().replace(tzinfo=timezone.utc).timestamp())
        if payload["exp"] <= current_timestamp:
            raise Exception(EXPIRED_TOKEN)

def generate_keypair():
    """Generate key files to keep safe or load existing public and private keys.

    Raises
    ------
    Exception
        If there was an error trying to load the JWT secret.
    """
    try:
        if not os.path.exists(_private_key_path) or not os.path.exists(_public_key_path):
            private_key, public_key = change_keypair()
            os.chmod(_private_key_path, 0o640)
            os.chmod(_public_key_path, 0o640)
        else:
            with open(_private_key_path, mode="r") as key_file:
                private_key = key_file.read()
            with open(_public_key_path, mode="r") as key_file:
                public_key = key_file.read()
    except Exception as e:
        raise e

    return private_key, public_key

def change_keypair():
    """Generate key files to keep safe."""
    key_obj = ec.generate_private_key(ec.SECP256R1())

    private_key = key_obj.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")

    public_key = key_obj.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")
    
    with open(_private_key_path, mode="w") as key_file:
        key_file.write(private_key)
    with open(_public_key_path, mode="w") as key_file:
        key_file.write(public_key)

    return private_key, public_key

def generate_token(uuid: str = None) -> str:
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
    timestamp = int(datetime.utcnow().replace(tzinfo=timezone.utc).timestamp())

    payload = {
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": timestamp,
        "exp": timestamp + JWT_EXPIRATION,
        "uuid": uuid,
        "can_send_commands": True # TODO: determine depending on whether it's a wazuh internal module or an agent
    }

    return jwt.encode(payload, generate_keypair()[0], algorithm=JWT_ALGORITHM)

def decode_token(token: str) -> dict:
    """Decode a JWT formatted token.

    Parameters
    ----------
    token : str
        JWT formatted token.

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
        return jwt.decode(token, generate_keypair()[1], algorithms=[JWT_ALGORITHM], audience=JWT_AUDIENCE)
    except jwt.exceptions.PyJWTError as exc:
        raise Exception(INVALID_TOKEN) from exc
