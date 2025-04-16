from enum import Enum
from typing import List, Optional

from pydantic import Field, PositiveInt, PrivateAttr, confloat, conint
from wazuh.core.common import WAZUH_GROUPS
from wazuh.core.config.models.base import WazuhConfigBaseModel
from wazuh.core.config.models.logging import LoggingConfig, LoggingLevel
from wazuh.core.config.models.ssl_config import SSLConfig

DEFAULT_CTI_URL = 'https://cti.wazuh.com'


class NodeType(str, Enum):
    """Enum representing supported nodes types."""

    WORKER = 'worker'
    MASTER = 'master'


class MasterIntervalsConfig(WazuhConfigBaseModel):
    """Configuration for master intervals.

    Parameters
    ----------
    timeout_extra_valid : PositiveInt
        The timeout for extra validation. Default is 40.
    recalculate_integrity : PositiveInt
        The interval for recalculating integrity. Default is 8.
    check_worker_last_keep_alive : PositiveInt
        The interval to check the last keep-alive from workers. Default is 60.
    max_allowed_time_without_keep_alive : PositiveInt
        The maximum allowed time without a keep-alive signal. Default is 120.
    max_locked_integrity_time : PositiveInt
        The maximum time for locked integrity. Default is 1000.
    """

    timeout_extra_valid: PositiveInt = 40
    recalculate_integrity: PositiveInt = 8
    check_worker_last_keep_alive: PositiveInt = 60
    max_allowed_time_without_keep_alive: PositiveInt = 120
    max_locked_integrity_time: PositiveInt = 1000


class MasterProcesses(WazuhConfigBaseModel):
    """Configuration for master processes.

    Parameters
    ----------
    process_pool_size : PositiveInt
        The size of the process pool. Default is 2.
    """

    process_pool_size: PositiveInt = 2


class MasterConfig(WazuhConfigBaseModel):
    """Configuration for the master node.

    Parameters
    ----------
    intervals : MasterIntervalsConfig
        Configuration for intervals related to the master.
    processes : MasterProcesses
        Configuration for processes related to the master.
    """

    intervals: MasterIntervalsConfig = MasterIntervalsConfig()
    processes: MasterProcesses = MasterProcesses()


class NodeConfig(WazuhConfigBaseModel):
    """Configuration for a node.

    Parameters
    ----------
    name : str
        The name of the node.
    type : Literal["master", "worker"]
        The type of the node (either master or worker).
    ssl : SSLConfig
        SSL configuration for the node.
    """

    name: str = Field(min_length=1)
    type: NodeType
    ssl: SSLConfig


class ZipConfig(WazuhConfigBaseModel):
    """Configuration for zip settings.

    Parameters
    ----------
    max_size : PositiveInt
        The maximum size of zip files. Default is 1 GiB.
    min_size : PositiveInt
        The minimum size of zip files. Default is 30 MiB.
    compress_level : conint(ge=0, le=9)
        The level of compression, from 0 (no compression) to 9 (maximum compression). Default is 1.
    limit_tolerance : confloat(ge=0.0, le=1.0)
        The tolerance limit for compression size. Default is 0.2.
    """

    max_size: PositiveInt = 1073741824
    min_size: PositiveInt = 31457280
    compress_level: conint(ge=0, le=9) = 1
    limit_tolerance: confloat(ge=0.0, le=1.0) = 0.2


class CommunicationsTimeoutConfig(WazuhConfigBaseModel):
    """Configuration for communication timeouts.

    Parameters
    ----------
    cluster_request : PositiveInt
        The timeout for cluster requests in seconds. Default is 20.
    dapi_request : PositiveInt
        The timeout for DAPI requests in seconds. Default is 200.
    receiving_file : PositiveInt
        The timeout for receiving files in seconds. Default is 120.
    """

    cluster_request: PositiveInt = 20
    dapi_request: PositiveInt = 200
    receiving_file: PositiveInt = 120


class CommunicationsConfig(WazuhConfigBaseModel):
    """Configuration for communications settings.

    Parameters
    ----------
    zip : ZipConfig
        Configuration for zip settings.
    timeouts : CommunicationsTimeoutConfig
        Configuration for communication timeouts.
    """

    zip: ZipConfig = ZipConfig()
    timeouts: CommunicationsTimeoutConfig = CommunicationsTimeoutConfig()


class WorkerIntervalsConfig(WazuhConfigBaseModel):
    """Configuration for worker intervals.

    Parameters
    ----------
    sync_integrity : PositiveInt
        The interval for synchronizing integrity. Default is 9.
    keep_alive : PositiveInt
        The interval for sending keep-alive signals. Default is 60.
    connection_retry : PositiveInt
        The number of retries for connection attempts. Default is 10.
    """

    sync_integrity: PositiveInt = 9
    keep_alive: PositiveInt = 60
    connection_retry: PositiveInt = 10


class WorkerRetriesConfig(WazuhConfigBaseModel):
    """Configuration for worker retries.

    Parameters
    ----------
    max_failed_keepalive_attempts : PositiveInt
        The maximum number of failed keep-alive attempts before considering the worker dead. Default is 2.
    """

    max_failed_keepalive_attempts: PositiveInt = 2


class WorkerConfig(WazuhConfigBaseModel):
    """Configuration for worker nodes.

    Parameters
    ----------
    intervals : WorkerIntervalsConfig
        Configuration for worker intervals.
    retries : WorkerRetriesConfig
        Configuration for worker retries.
    """

    intervals: WorkerIntervalsConfig = WorkerIntervalsConfig()
    retries: WorkerRetriesConfig = WorkerRetriesConfig()


class SharedFiles(WazuhConfigBaseModel):
    """Configuration for shared files.

    Parameters
    ----------
    dir : str
        The directory containing shared files.
    description : str
        A description of the shared files.
    permissions : PositiveInt
        The permissions for the shared files.
    source : str
        The source of the shared files.
    names : List[str]
        The names of the shared files.
    recursive : bool
        Whether to search for files recursively.
    restart : bool
        Whether to restart the service when these files change.
    remove_subdirs_if_empty : bool
        Whether to remove subdirectories if they are empty.
    extra_valid : bool
        Whether to perform extra validation.
    """

    dir: str
    description: str
    permissions: PositiveInt
    source: str
    names: List[str]
    recursive: bool
    restart: bool
    remove_subdirs_if_empty: bool
    extra_valid: bool


class ServerSyncConfig(WazuhConfigBaseModel):
    """Configuration for server internal settings.

    Parameters
    ----------
    files : List[SharedFiles]
        List of shared file configurations.
    excluded_files : List[str]
        List of files to be excluded.
    excluded_extensions : List[str]
        List of file extensions to be excluded.
    """

    files: List[SharedFiles]
    excluded_files: List[str]
    excluded_extensions: List[str]

    def get_dir_config(self, name: str) -> Optional[SharedFiles]:
        """Retrieve the shared file configuration for a given directory name.

        Parameters
        ----------
        name : str
            The name of the directory to look up.

        Returns
        -------
        Optional[SharedFiles]
            The configuration for the shared files in the specified directory,
            or None if not found.
        """
        for file in self.files:
            if file.dir == name:
                return file

        return None


class CTIConfig(WazuhConfigBaseModel):
    """Configuration for CTI settings.

    Parameters
    ----------
    update_check : bool
        Whether to perform an update check. Default is True.
    url : str
        The URL for the CTI service. Default is "https://cti.wazuh.com".
    """

    update_check: bool = True
    url: str = DEFAULT_CTI_URL


DEFAULT_SERVER_INTERNAL_CONFIG = ServerSyncConfig(
    files=[
        SharedFiles(
            dir=WAZUH_GROUPS.as_posix(),
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
    excluded_files=[],
    excluded_extensions=['~', '.tmp', '.lock', '.swp'],
)


class ServerConfig(WazuhConfigBaseModel):
    """Configuration for the server.

    Parameters
    ----------
    port : PositiveInt
        The port on which the server will listen. Default is 1516.
    bind_addr : str
        The address to bind to. Default is "localhost".
    nodes : List[str]
        List of nodes in the server.
    hidden : bool
        Whether the server is hidden. Default is False.
    update_check : bool
        Whether to perform an update check. Default is False.
    node : NodeConfig
        Configuration for the server node.
    worker : WorkerConfig
        Configuration for worker nodes. Default is WorkerConfig().
    master : MasterConfig
        Configuration for the master node. Default is MasterConfig().
    communications : CommunicationsConfig
        Configuration for communications. Default is CommunicationsConfig().
    logging : LoggingConfig
        Logging configuration. Default is LoggingConfig(level="debug2").
    cti : CTIConfig
        Configuration for CTI settings. Default is CTIConfig().
    _internal : ServerSyncConfig
        Internal server configurations. These settings are internal
    """

    port: PositiveInt = 1516
    bind_addr: str = 'localhost'
    nodes: List[str] = Field(min_length=1)
    hidden: bool = False
    update_check: bool = False

    node: NodeConfig
    worker: WorkerConfig = WorkerConfig()
    master: MasterConfig = MasterConfig()
    communications: CommunicationsConfig = CommunicationsConfig()
    logging: LoggingConfig = LoggingConfig(level=LoggingLevel.info)
    cti: CTIConfig = CTIConfig()
    _internal: ServerSyncConfig = PrivateAttr(DEFAULT_SERVER_INTERNAL_CONFIG)

    def get_internal_config(self) -> ServerSyncConfig:
        """Retrieve the internal server configuration.

        Returns
        -------
        ServerSyncConfig
            The internal configuration for the server.
        """
        return self._internal
