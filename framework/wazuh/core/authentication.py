from functools import lru_cache

from cryptography.hazmat.primitives import serialization
from wazuh.core.config.client import CentralizedConfig

JWT_ALGORITHM = 'RS256'
JWT_ISSUER = 'wazuh'


@lru_cache(maxsize=None)
def get_keypair() -> tuple[str, str]:
    """Return key files to keep safe or load existing public and private keys.

    Returns
    -------
    private_key : str
        Private key.
    public_key : str
        Public key.
    """
    config = CentralizedConfig.get_management_api_config()

    with open(config.ssl.key, mode='r') as key_file:
        private_key = key_file.read()
        encoded_private_key = serialization.load_pem_private_key(private_key.encode('utf-8'), password=None)

    public_key = (
        encoded_private_key.public_key()
        .public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode('utf-8')
    )

    return private_key, public_key
