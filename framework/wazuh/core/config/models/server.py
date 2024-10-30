from pydantic import BaseModel, PositiveInt, conint, confloat
from typing import List, Literal

from wazuh.core.config.models.ssl_config import SSLConfig


class MasterIntervalsConfig(BaseModel):
    timeout_extra_valid: PositiveInt = 40
    recalculate_integrity: PositiveInt = 8
    check_worker_last_keepalive: PositiveInt = 60
    max_allowed_time_without_keepalive: PositiveInt = 120
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


class ServerConfig(BaseModel):
    port: PositiveInt = 1516
    bind_addr: str = "localhost"
    nodes: List[str] = ["master"]
    hidden: bool = False

    node: NodeConfig = NodeConfig()
    worker: WorkerConfig = WorkerConfig()
    master: MasterConfig = MasterConfig()
    communications: CommunicationsConfig = CommunicationsConfig()


