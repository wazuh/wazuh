from pydantic import BaseModel, PositiveInt, conint, confloat, PrivateAttr
from typing import List, Literal, Optional

from wazuh.core.config.models.ssl_config import SSLConfig
from wazuh.core.config.models.logging import LoggingConfig


class MasterIntervalsConfig(BaseModel):
    timeout_extra_valid: PositiveInt = 40
    recalculate_integrity: PositiveInt = 8
    check_worker_last_keep_alive: PositiveInt = 60
    max_allowed_time_without_keep_alive: PositiveInt = 120
    max_locked_integrity_time: PositiveInt = 1000


class MasterProcesses(BaseModel):
    process_pool_size: PositiveInt = 2


class MasterConfig(BaseModel):
    intervals: MasterIntervalsConfig = MasterIntervalsConfig()
    processes: MasterProcesses = MasterProcesses()


class NodeConfig(BaseModel):
    name: str = "manager_01"
    type: Literal["master", "worker"] = "master"
    ssl: SSLConfig = SSLConfig(
        key="var/ossec/etc/etc/sslmanager.key",
        cert="var/ossec/etc/sslmanager.cert",
        ca="var/ossec/etc/sslmanager.ca"
    )


class ZipConfig(BaseModel):
    max_size: PositiveInt = 1073741824
    min_size: PositiveInt = 31457280
    compress_level: conint(ge=0, le=9) = 1
    limit_tolerance: confloat(ge=0.0, le=1.0) = 0.2


class CommunicationsTimeoutConfig(BaseModel):
    cluster_request: PositiveInt = 20
    dapi_request: PositiveInt = 200
    receiving_file: PositiveInt = 120


class CommunicationsConfig(BaseModel):
    zip: ZipConfig = ZipConfig()
    timeouts: CommunicationsTimeoutConfig = CommunicationsTimeoutConfig()


class WorkerIntervalsConfig(BaseModel):
    sync_integrity: PositiveInt = 9
    keep_alive: PositiveInt = 60
    connection_retry: PositiveInt = 10


class WorkerRetriesConfig(BaseModel):
    max_failed_keepalive_attempts: PositiveInt = 2


class WorkerConfig(BaseModel):
    intervals: WorkerIntervalsConfig = WorkerIntervalsConfig()
    retries: WorkerRetriesConfig = WorkerRetriesConfig()


class SharedFiles(BaseModel):
    dir: str
    description: str
    permissions: PositiveInt
    source: str
    names: List[str]
    recursive: bool
    restart: bool
    remove_subdirs_if_empty: bool
    extra_valid: bool


class ServerInternalConfig(BaseModel):
    files: List[SharedFiles]
    excluded_files: List[str]
    excluded_extensions: List[str]

    def get_dir_config(self, name: str) -> Optional[SharedFiles]:
        for file in self.files:
            if file.dir == name:
                return file

        return None


class ServerConfig(BaseModel):
    port: PositiveInt = 1516
    bind_addr: str = "localhost"
    nodes: List[str] = ["master"]
    hidden: bool = False

    node: NodeConfig = NodeConfig()
    worker: WorkerConfig = WorkerConfig()
    master: MasterConfig = MasterConfig()
    communications: CommunicationsConfig = CommunicationsConfig()
    logging: LoggingConfig = LoggingConfig(level="debug")
    internal: ServerInternalConfig = PrivateAttr(
        ServerInternalConfig(
            files=[
                SharedFiles(
                    dir="etc/",
                    description="JWT signing key pair",
                    permissions=416,
                    source="master",
                    names=["private_key.pem", "public_key.pem"],
                    recursive=False,
                    restart=False,
                    remove_subdirs_if_empty=False,
                    extra_valid=False,
                ),
                SharedFiles(
                    dir='etc/shared/',
                    description='group files',
                    permissions=432,
                    source='master',
                    names=['all'],
                    recursive=False,
                    restart=False,
                    remove_subdirs_if_empty=True,
                    extra_valid=False,
                ),
            ],
            excluded_files=['ar.conf'],
            excluded_extensions=['~', '.tmp', '.lock', '.swp']
        )
    )

    def get_internal_config(self) -> ServerInternalConfig:
        return self.internal
