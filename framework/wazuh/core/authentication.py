import os
from typing import Tuple
from cryptography.hazmat.primitives import serialization

from wazuh import WazuhInternalError
from wazuh.core.config.client import CentralizedConfig
from wazuh.core.common import wazuh_uid, wazuh_gid

JWT_ALGORITHM = 'ES256'
JWT_ISSUER = 'wazuh'
# TODO(27776) - Change to use paths
_public_key_path = '/etc/wazuh-server/certs/public-key.pem'


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

    if not os.path.exists(config.jwt.private_key):
        raise WazuhInternalError(6003)
    elif not os.path.exists(_public_key_path):
        try:
            create_public_key(config.jwt.private_key, _public_key_path)
            os.chown(_public_key_path, wazuh_uid(), wazuh_gid())
            os.chmod(_public_key_path, 0o640)
        except PermissionError:
            pass

    with open(config.jwt.private_key, mode='r') as key_file:
        private_key = key_file.read()
    with open(config.jwt.public_key, mode='r') as key_file:
        public_key = key_file.read()

    return private_key, public_key


def create_public_key(private_key_path: str, public_key_path: str):
    """Generate public key

    Returns
    -------
    private_key_path : str
        Private key path.
    public_key_path : str
        Public key path.
    """
    with open(private_key_path) as private_key_file:
        private_key_contents = private_key_file.read()

        private_key = serialization.load_pem_private_key(
            private_key_contents.encode('utf-8'),
            password=None
        )

    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    with open(public_key_path, mode='w') as public_key_file:
        public_key_file.write(public_key)
