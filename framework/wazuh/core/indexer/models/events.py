from dataclasses import dataclass
from datetime import datetime
from typing import List, Union

from pydantic import BaseModel

from wazuh.core.indexer.models.commands import Result
from wazuh.core.indexer.commands import CommandsManager

FIM_INDEX = 'wazuh-states-fim'
INVENTORY_PACKAGES_INDEX = 'wazuh-states-inventory-packages'
INVENTORY_SYSTEM_INDEX = 'wazuh-states-inventory-system'
SCA_INDEX = 'stateful-sca'
VULNERABILITY_INDEX = 'wazuh-states-vulnerabilities'


@dataclass
class TaskResult:
    """Stateful event bulk task result data model."""
    id: str
    result: str
    status: int


class EventAgent:
    """Agent data model in relation to events."""
    id: str
    groups: str


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
class FIMEvent(BaseModel):
    """FIM events data model."""
    agent: EventAgent
    file: File
    registry: Registry

    def get_index_name(self) -> str:
        """Get the index name for the event type.
        
        Returns
        -------
        str
            Index name.
        """
        return FIM_INDEX


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
class ProcessHash:
    md5: str


@dataclass
class Process:
    """Process data model."""
    hash: ProcessHash


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
class InventoryPackageEvent(BaseModel):
    """Inventory packages events data model."""
    agent: EventAgent
    scan_time: datetime
    package: Package

    def get_index_name(self) -> str:
        """Get the index name for the event type.
        
        Returns
        -------
        str
            Index name.
        """
        return INVENTORY_PACKAGES_INDEX


@dataclass
class InventorySystemEvent(BaseModel):
    """Inventory system events data model."""
    agent: EventAgent
    scan_time: datetime
    host: Host

    def get_index_name(self) -> str:
        """Get the index name for the event type.
        
        Returns
        -------
        str
            Index name.
        """
        return INVENTORY_SYSTEM_INDEX


@dataclass
class SCAEvent(BaseModel):
    """SCA events data model."""
    # TODO(25121): Update SCA event fields

    def get_index_name(self) -> str:
        """Get the index name for the event type.
        
        Returns
        -------
        str
            Index name.
        """
        return SCA_INDEX


@dataclass
class VulnerabilityEventAgent:
    """Agent data model in relation to vulnerability events."""
    id: str
    groups: str
    name: str
    type: str
    version: str


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
class VulnerabilityEvent(BaseModel):
    """Vulnerability events data model."""
    agent: VulnerabilityEventAgent
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

    def get_index_name(self) -> str:
        """Get the index name for the event type.
        
        Returns
        -------
        str
            Index name.
        """
        return VULNERABILITY_INDEX


@dataclass
class CommandResult(BaseModel):
    """Command result data model."""
    document_id: str
    result: Result

    def get_index_name(self) -> str:
        """Get the index name for the event type.
        
        Returns
        -------
        str
            Index name.
        """
        return CommandsManager.INDEX


# Stateful event type
StatefulEvent = Union[FIMEvent, InventoryPackageEvent, InventorySystemEvent, SCAEvent, VulnerabilityEvent]
