from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict, List, Union

from wazuh.core.exception import WazuhError
from wazuh.core.indexer.models.commands import Result
from wazuh.core.indexer.commands import CommandsManager

FIM_INDEX = 'wazuh-states-fim'
INVENTORY_NETWORK_INDEX = 'wazuh-states-inventory-network'
INVENTORY_PACKAGES_INDEX = 'wazuh-states-inventory-packages'
INVENTORY_PROCESSES_INDEX = 'wazuh-states-inventory-processes'
INVENTORY_SYSTEM_INDEX = 'wazuh-states-inventory-system'
SCA_INDEX = 'wazuh-states-sca'
VULNERABILITY_INDEX = 'wazuh-states-vulnerabilities'
INVENTORY_NETWORK_TYPE = 'network'
INVENTORY_PACKAGES_TYPE = 'package'
INVENTORY_PROCESSES_TYPE = 'process'
INVENTORY_SYSTEM_TYPE = 'system'


@dataclass
class AgentMetadata:
    """Agent metadata."""
    uuid: str
    groups: List[str]
    os: str
    platform: str
    arch: str
    type: str
    version: str
    ip: str


@dataclass
class TaskResult:
    """Stateful event bulk task result data model."""
    id: str
    result: str
    status: int


@dataclass
class Hash:
    """Hash data model."""
    md5: str
    sha1: str
    sha256: str


@dataclass
class File:
    """File data model."""
    attributes: List[str]
    name: str
    path: str
    gid: int
    group: str
    inode: str
    mtime: datetime
    mode: str
    size: float
    target_path: str
    type: str
    uid: int
    owner: str
    hash: Hash


@dataclass
class Registry:
    """Registry data model."""
    key: str
    value: str


@dataclass
class FIMEvent:
    """FIM events data model."""
    file: File
    registry: Registry


@dataclass
class InventoryNetworkEvent:
    """Inventory network events data model."""
    # TODO(25121): Add inventory network fields once they are defined


@dataclass
class OS:
    """OS data model."""
    kernel: str
    full: str
    name: str
    platform: str
    version: str
    type: str


@dataclass
class Host:
    """Host data model."""
    architecture: str
    hostname: str
    os: OS


@dataclass
class Package:
    """Package data model."""
    architecture: str
    description: str
    installed: datetime
    name: str
    path: str
    size: float
    type: str
    version: str


@dataclass
class InventoryPackageEvent:
    """Inventory packages events data model."""
    scan_time: datetime
    package: Package


@dataclass
class Parent:
    """Process parent data model."""
    pid: float


@dataclass
class ID:
    """Process users and groups ID data model."""
    id: str


@dataclass
class Process:
    """Process data model."""
    pid: float
    name: str
    parent: Parent
    command_line: str
    args: List[str]
    user: ID
    real_user: ID
    saved_user: ID
    group: ID
    real_group: ID
    saved_group: ID
    start: datetime
    thread: ID


@dataclass
class InventoryProcessEvent:
    """Inventory process events data model."""
    scan_time: datetime
    process: Process


@dataclass
class InventorySystemEvent:
    """Inventory system events data model."""
    scan_time: datetime
    host: Host


@dataclass
class SCAEvent:
    """SCA events data model."""
    # TODO(25121): Add SCA event fields once they are defined


@dataclass
class VulnerabilityEventHost:
    """Host data model in relation to vulnerability events."""
    os: OS


@dataclass
class VulnerabilityEventPackage:
    """Package data model in relation to vulnerability events."""
    architecture: str
    build_version: str
    checksum: str
    description: str
    install_scope: str
    installed: datetime
    license: str
    name: str
    path: str
    reference: str
    size: float
    type: str
    version: str


@dataclass
class Cluster:
    """Wazuh cluster data model."""
    name: str
    node: str


@dataclass
class Schema:
    """Wazuh schema data model."""
    version: str


@dataclass
class Wazuh:
    """Wazuh instance information data model."""
    cluster: Cluster
    schema: Schema


@dataclass
class Scanner:
    """Scanner data model."""
    source: str
    vendor: str


@dataclass
class Score:
    """Score data model."""
    base: float
    environmental: float
    temporal: float
    version: str


@dataclass
class VulnerabilityEvent:
    """Vulnerability events data model."""
    host: VulnerabilityEventHost
    package: VulnerabilityEventPackage
    scanner: Scanner
    score: Score
    category: str
    classification: str
    description: str
    detected_at: datetime
    enumeration: str
    id: str
    published_at: datetime
    reference: str
    report_id: str
    severity: str
    under_evaluation: bool


@dataclass
class CommandResult:
    """Command result data model."""
    result: Result


class ModuleName(str, Enum):
    """Stateful event module name."""
    FIM = 'fim'
    INVENTORY = 'inventory'
    SCA = 'sca'
    VULNERABILITY = 'vulnerability'
    COMMAND = 'command'


@dataclass
class Module:
    """Stateful event module."""
    document_id: str
    name: ModuleName
    type: str = None


@dataclass
class StatefulEvent:
    """Stateful event data model."""
    data: Union[
        FIMEvent,
        InventoryNetworkEvent,
        InventoryPackageEvent,
        InventoryProcessEvent,
        InventorySystemEvent,
        SCAEvent,
        VulnerabilityEvent,
        CommandResult
    ]
    module: Module


STATEFUL_EVENTS_INDICES: Dict[ModuleName, str] = {
    ModuleName.FIM: FIM_INDEX,
    ModuleName.SCA: SCA_INDEX,
    ModuleName.VULNERABILITY: VULNERABILITY_INDEX,
    ModuleName.COMMAND: CommandsManager.INDEX
}


def get_module_index_name(module: Module) -> str:
    """Get the index name corresponding to the specified module.

    Parameters
    ----------
    module : Module
        Event module.
    
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
    if module.name == ModuleName.INVENTORY:
        if module.type == INVENTORY_PACKAGES_TYPE:
            return INVENTORY_PACKAGES_INDEX
        if module.type == INVENTORY_PROCESSES_TYPE:
            return INVENTORY_PROCESSES_INDEX
        if module.type == INVENTORY_NETWORK_TYPE:
            return INVENTORY_NETWORK_INDEX
        if module.type == INVENTORY_SYSTEM_TYPE:
            return INVENTORY_SYSTEM_INDEX

        raise WazuhError(1763)

    try:
        return STATEFUL_EVENTS_INDICES[module.name]
    except KeyError:
        raise WazuhError(1765)
