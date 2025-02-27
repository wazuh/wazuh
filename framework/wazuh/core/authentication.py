import contextlib
import os

from cryptography.hazmat.primitives import serialization
from wazuh.core import common
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.config.models.base import WazuhConfigBaseModel

JWT_ALGORITHM = 'RS256'
JWT_ISSUER = 'wazuh'


def check_jwt_keys(api_config: WazuhConfigBaseModel):
    """Verify if JWT key files are configured and generate them if not."""
    config = CentralizedConfig.get_server_config()
    if config.jwt.private_key and config.jwt.public_key:
        return

    # Generate keys from defined SSL key path
    public_key = generate_jwt_public_key(api_config.ssl.key)

    # Assign API SSL key as JWT private key and default JWT Public Key path
    config.jwt.private_key = api_config.ssl.key
    config.jwt.set_public_key(public_key)


def generate_jwt_public_key(private_key_path: str) -> str:
    """Generate public key for JWT from the API SSL certificate private key.

    Returns
    -------
    str
        Public key.
    """
    with open(private_key_path, mode='r') as key_file:
        private_key_content = key_file.read()
        private_key = serialization.load_pem_private_key(private_key_content.encode('utf-8'), password=None)

    public_key = (
        private_key.public_key()
        .public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode('utf-8')
    )

    return public_key


def get_keypair() -> tuple[str, str]:
    """Return key files to keep safe or load existing public and private keys.

    Returns
    -------
    private_key : str
        Private key.
    public_key : str
        Public key.
    """
    config = CentralizedConfig.get_server_config()

    with open(config.jwt.private_key, mode='r') as key_file:
        private_key = key_file.read()
    public_key = config.jwt.get_public_key()

    return private_key, public_key
