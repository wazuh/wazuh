from pydantic import BaseModel
from typing import Literal


class SSLConfig(BaseModel):
    key: str
    cert: str
    ca: str
    keyfile_password: str = ""


class IndexerSSLConfig(BaseModel):
    use_ssl: bool = False
    key: str = ""
    cert: str = ""
    ca: str = ""


class APISSLConfig(BaseModel):
    key: str
    cert: str
    use_ca: bool = False
    ca: str = ""
    ssl_protocol: Literal["TLS", "TLSv1", "TLSv1.1", "TLSv1.2", "auto"] = "auto"
    ssl_ciphers: str = ""

