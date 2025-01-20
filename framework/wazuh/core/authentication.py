from typing import Tuple

from wazuh.core.config.client import CentralizedConfig

JWT_ALGORITHM = 'ES256'
JWT_ISSUER = 'wazuh'


def get_keypair() -> Tuple[str, str]:
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
    with open(config.jwt.public_key, mode='r') as key_file:
        public_key = key_file.read()

    return private_key, public_key
