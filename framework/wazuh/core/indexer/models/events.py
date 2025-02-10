from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel
from wazuh.core.exception import WazuhError
from wazuh.core.indexer.bulk import Operation
from wazuh.core.indexer.commands import CommandsManager
from wazuh.core.indexer.models.agent import Host as AgentHost

FIM_INDEX = 'wazuh-states-fim'
INVENTORY_HARDWARE_INDEX = 'wazuh-states-inventory-hardware'
INVENTORY_HOTFIXES_INDEX = 'wazuh-states-inventory-hotfixes'
INVENTORY_NETWORKS_INDEX = 'wazuh-states-inventory-networks'
INVENTORY_PACKAGES_INDEX = 'wazuh-states-inventory-packages'
INVENTORY_PORTS_INDEX = 'wazuh-states-inventory-ports'
INVENTORY_PROCESSES_INDEX = 'wazuh-states-inventory-processes'
INVENTORY_SYSTEM_INDEX = 'wazuh-states-inventory-system'
SCA_INDEX = 'wazuh-states-sca'
VULNERABILITY_INDEX = 'wazuh-states-vulnerabilities'


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

    index: str
    id: str
    result: str
    status: int


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
    collector: Optional[str] = None
    operation: Operation = None


class Collector(str, Enum):
    """Stateful events inventory collector."""

    HARDWARE = 'hardware'
    HOTFIXES = 'hotfixes'
    PACKAGES = 'packages'
    NETWORKS = 'networks'
    SYSTEM = 'system'
    PORTS = 'ports'
    PROCESSES = 'processes'


STATEFUL_EVENTS_INDICES: Dict[Module, str] = {
    Module.FIM: FIM_INDEX,
    Module.SCA: SCA_INDEX,
    Module.VULNERABILITY: VULNERABILITY_INDEX,
    Module.COMMAND: CommandsManager.INDEX,
}

INVENTORY_EVENTS: Dict[Collector, str] = {
    Collector.HARDWARE: INVENTORY_HARDWARE_INDEX,
    Collector.HOTFIXES: INVENTORY_HOTFIXES_INDEX,
    Collector.PACKAGES: INVENTORY_PACKAGES_INDEX,
    Collector.NETWORKS: INVENTORY_NETWORKS_INDEX,
    Collector.SYSTEM: INVENTORY_SYSTEM_INDEX,
    Collector.PORTS: INVENTORY_PORTS_INDEX,
    Collector.PROCESSES: INVENTORY_PROCESSES_INDEX,
}


def get_module_index_name(module: Module, collector: Optional[str] = None) -> str:
    """Get the index name corresponding to the specified module and type.

    Parameters
    ----------
    module : Module
        Event module.
    collector : Optional[str]
        Event module collector.

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
        collectors = list(INVENTORY_EVENTS.keys())
        if collector not in collectors:
            extra_info = {'collectors': ', '.join(collectors[:-1]) + ' or ' + collectors[-1]}
            raise WazuhError(1763, extra_message=extra_info)

        return INVENTORY_EVENTS[collector]

    try:
        return STATEFUL_EVENTS_INDICES[module]
    except KeyError:
        modules = list(STATEFUL_EVENTS_INDICES.keys())
        extra_info = {'modules': ', '.join(modules[:-1]) + ' or ' + modules[-1]}
        raise WazuhError(1765, extra_message=extra_info)
