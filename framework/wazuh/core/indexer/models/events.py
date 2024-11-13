from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Union

from pydantic import BaseModel

from wazuh.core.exception import WazuhError
from wazuh.core.indexer.bulk import Operation
from wazuh.core.indexer.commands import CommandsManager
from wazuh.core.indexer.models.agent import Host as AgentHost
from wazuh.core.indexer.models.commands import Result

FIM_INDEX = 'wazuh-states-fim'
INVENTORY_NETWORKS_INDEX = 'wazuh-states-inventory-networks'
INVENTORY_PACKAGES_INDEX = 'wazuh-states-inventory-packages'
INVENTORY_PROCESSES_INDEX = 'wazuh-states-inventory-processes'
INVENTORY_SYSTEM_INDEX = 'wazuh-states-inventory-system'
SCA_INDEX = 'wazuh-states-sca'
VULNERABILITY_INDEX = 'wazuh-states-vulnerabilities'
INVENTORY_NETWORKS_TYPE = 'networks'
INVENTORY_PACKAGES_TYPE = 'packages'
INVENTORY_PROCESSES_TYPE = 'processes'
INVENTORY_SYSTEM_TYPE = 'system'


class Agent(BaseModel):
    """Agent model in the context of events."""
    id: str
    name: str
    groups: List[str]
    type: str
    version: str
    host: AgentHost


class AgentMetadata(BaseModel):
    """Agent metadata."""
    agent: Agent


class TaskResult(BaseModel):
    """Stateful event bulk task result data model."""
    id: str
    result: str
    status: int


class Hash(BaseModel):
    """Hash data model."""
    md5: str = None
    sha1: str = None
    sha256: str = None


class File(BaseModel):
    """File data model."""
    attributes: List[str] = None
    name: str = None
    path: str = None
    gid: int = None
    group: str = None
    inode: str = None
    mtime: datetime = None
    mode: str = None
    size: float = None
    target_path: str = None
    type: str = None
    uid: int = None
    owner: str = None
    hash: Hash = None


class Registry(BaseModel):
    """Registry data model."""
    key: str = None
    value: str = None


class FIMEvent(BaseModel):
    """FIM events data model."""
    file: File = None
    registry: Registry = None


class InventoryNetworkEvent(BaseModel):
    """Inventory network events data model."""
    # TODO(25121): Add inventory network fields once they are defined


class OS(BaseModel):
    """OS data model."""
    kernel: str = None
    full: str = None
    name: str = None
    platform: str = None
    version: str = None
    type: str = None


class Host(BaseModel):
    """Host data model."""
    architecture: str = None
    hostname: str = None
    os: OS = None


class Package(BaseModel):
    """Package data model."""
    architecture: str = None
    description: str = None
    installed: datetime = None
    name: str = None
    path: str = None
    size: float = None
    type: str = None
    version: str = None


class InventoryPackageEvent(BaseModel):
    """Inventory packages events data model."""
    scan_time: datetime = None
    package: Package = None


class Parent(BaseModel):
    """Process parent data model."""
    pid: float = None


class ID(BaseModel):
    """Process users and groups ID data model."""
    id: str = None


class Process(BaseModel):
    """Process data model."""
    pid: float = None
    name: str = None
    parent: Parent = None
    command_line: str = None
    args: List[str] = None
    user: ID = None
    real_user: ID = None
    saved_user: ID = None
    group: ID = None
    real_group: ID = None
    saved_group: ID = None
    start: datetime = None
    thread: ID = None


class InventoryProcessEvent(BaseModel):
    """Inventory process events data model."""
    scan_time: datetime = None
    process: Process = None


class InventorySystemEvent(BaseModel):
    """Inventory system events data model."""
    scan_time: datetime = None
    host: Host = None


class SCAEvent(BaseModel):
    """SCA events data model."""
    # TODO(25121): Add SCA event fields once they are defined


class VulnerabilityEventHost(BaseModel):
    """Host data model in relation to vulnerability events."""
    os: OS = None


class VulnerabilityEventPackage(BaseModel):
    """Package data model in relation to vulnerability events."""
    architecture: str = None
    build_version: str = None
    checksum: str = None
    description: str = None
    install_scope: str = None
    installed: datetime = None
    license: str = None
    name: str = None
    path: str = None
    reference: str = None
    size: float = None
    type: str = None
    version: str = None


class Scanner(BaseModel):
    """Scanner data model."""
    source: str = None
    vendor: str = None


class Score(BaseModel):
    """Score data model."""
    base: float = None
    environmental: float = None
    temporal: float = None
    version: str = None


class VulnerabilityEvent(BaseModel):
    """Vulnerability events data model."""
    host: VulnerabilityEventHost = None
    package: VulnerabilityEventPackage = None
    scanner: Scanner = None
    score: Score = None
    category: str = None
    classification: str = None
    description: str = None
    detected_at: datetime = None
    enumeration: str = None
    id: str = None
    published_at: datetime = None
    reference: str = None
    report_id: str = None
    severity: str = None
    under_evaluation: bool = None


class CommandResult(BaseModel):
    """Command result data model."""
    result: Result


class Module(str, Enum):
    """Stateful event module name."""
    FIM = 'fim'
    INVENTORY = 'inventory'
    SCA = 'sca'
    VULNERABILITY = 'vulnerability'
    COMMAND = 'command'


class Header(BaseModel):
    """Stateful event header."""
    id: Optional[str] = None
    module: Module
    type: Optional[str] = None
    operation: Operation = None


StatefulEvent = Union[
    FIMEvent,
    InventoryNetworkEvent,
    InventoryPackageEvent,
    InventoryProcessEvent,
    InventorySystemEvent,
    SCAEvent,
    VulnerabilityEvent,
    CommandResult
]


STATEFUL_EVENTS_INDICES: Dict[Module, str] = {
    Module.FIM: FIM_INDEX,
    Module.SCA: SCA_INDEX,
    Module.VULNERABILITY: VULNERABILITY_INDEX,
    Module.COMMAND: CommandsManager.INDEX
}


def get_module_index_name(module: Module, type: Optional[str] = None) -> str:
    """Get the index name corresponding to the specified module and type.

    Parameters
    ----------
    module : Module
        Event module.
    type : Optional[str]
        Event module type
    
    Raises
    ------
    WazuhError(1763)
        Invalid inventory module type error.
    WazuhError(1765)
        Invalid module name.
    
    Returns
    -------
    str
        Index name.
    """
    if module == Module.INVENTORY:
        if type == INVENTORY_PACKAGES_TYPE:
            return INVENTORY_PACKAGES_INDEX
        if type == INVENTORY_PROCESSES_TYPE:
            return INVENTORY_PROCESSES_INDEX
        if type == INVENTORY_NETWORKS_TYPE:
            return INVENTORY_NETWORKS_INDEX
        if type == INVENTORY_SYSTEM_TYPE:
            return INVENTORY_SYSTEM_INDEX

        raise WazuhError(1763)

    try:
        return STATEFUL_EVENTS_INDICES[module]
    except KeyError:
        raise WazuhError(1765)
