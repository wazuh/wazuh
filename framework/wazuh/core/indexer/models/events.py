from dataclasses import dataclass
from datetime import datetime
from typing import List, Union

from pydantic import BaseModel

from wazuh.core.indexer.models.commands import Result
from wazuh.core.indexer.commands import CommandsManager

FIM_INDEX = 'stateful-fim'
INVENTORY_INDEX = 'stateful-inventory'
SCA_INDEX = 'stateful-sca'
VULNERABILITY_INDEX = 'stateful-vulnerability'


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
class FIMEvent(BaseModel):
    """FIM events data model."""
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
    family: str


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
class InventoryEvent(BaseModel):
    """Inventory events data model."""
    host: Host
    process: Process

    def get_index_name(self) -> str:
        """Get the index name for the event type.
        
        Returns
        -------
        str
            Index name.
        """
        return INVENTORY_INDEX


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
class BuildInfo:
    """Agent build information data model."""
    original: str


@dataclass
class EventAgent:
    """Agent data model in relation to events."""
    build: BuildInfo
    ephemeral_id: str
    id: str
    name: str
    type: str
    version: str


@dataclass
class Package:
    """Package data model."""
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
class Manager:
    """Wazuh manager data model."""
    name: str


@dataclass
class Schema:
    """Wazuh schema data model."""
    version: str


@dataclass
class Wazuh:
    """Wazuh instance information data model."""
    cluster: Cluster
    manager: Manager
    schema: Schema


@dataclass
class VulnerabilityEvent(BaseModel):
    """Vulnerability events data model."""
    agent: EventAgent
    host: Host
    message: str
    package: Package
    tags: List[str]

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
StatefulEvent = Union[FIMEvent, InventoryEvent, SCAEvent, VulnerabilityEvent, CommandResult]
