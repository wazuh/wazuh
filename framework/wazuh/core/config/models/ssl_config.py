from pydantic import BaseModel
from typing import Literal


class SSLConfig(BaseModel):
    """Configuration for SSL settings specific to the server.

    Parameters
    ----------
    key : str
        The path to the SSL key file.
    cert : str
        The path to the SSL certificate file.
    ca : str
        The path to the CA certificate file.
    keyfile_password : str
        The password for the SSL key file. Default is an empty string.
    """
    key: str
    cert: str
    ca: str
    keyfile_password: str = ""


class IndexerSSLConfig(BaseModel):
    """Configuration for SSL settings specific to the indexer.

    Parameters
    ----------
    use_ssl : bool
        Whether to use SSL for the indexer. Default is False.
    key : str
        The path to the SSL key file. Default is an empty string.
    cert : str
        The path to the SSL certificate file. Default is an empty string.
    ca : str
        The path to the CA certificate file. Default is an empty string.
    """
    use_ssl: bool = False
    key: str = ""
    cert: str = ""
    ca: str = ""


class APISSLConfig(BaseModel):
    """Configuration for API SSL settings.

    Parameters
    ----------
    key : str
        The path to the SSL key file.
    cert : str
        The path to the SSL certificate file.
    use_ca : bool
        Whether to use a CA certificate. Default is False.
    ca : str
        The path to the CA certificate file. Default is an empty string.
    ssl_protocol : Literal["TLS", "TLSv1", "TLSv1.1", "TLSv1.2", "auto"]
        The SSL protocol to use. Default is "auto".
    ssl_ciphers : str
        The SSL ciphers to use. Default is an empty string.
    """
    key: str
    cert: str
    use_ca: bool = False
    ca: str = ""
    ssl_protocol: Literal["TLS", "TLSv1", "TLSv1.1", "TLSv1.2", "auto"] = "auto"
    ssl_ciphers: str = ""

