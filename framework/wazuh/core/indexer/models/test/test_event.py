import pytest

from wazuh.core.exception import WazuhError
from wazuh.core.indexer.models.events import get_module_index_name, Module, FIM_INDEX, SCA_INDEX, \
    VULNERABILITY_INDEX, INVENTORY_NETWORKS_INDEX, INVENTORY_PACKAGES_INDEX, INVENTORY_PROCESSES_INDEX, \
    INVENTORY_SYSTEM_INDEX, INVENTORY_HOTFIXES_INDEX, INVENTORY_PORTS_INDEX, INVENTORY_HARDWARE_INDEX, \
    InventoryType, CommandsManager


@pytest.mark.parametrize('module, type, expected_name', [
    (Module.INVENTORY, InventoryType.HARDWARE, INVENTORY_HARDWARE_INDEX),
    (Module.INVENTORY, InventoryType.HOTFIXES, INVENTORY_HOTFIXES_INDEX),
    (Module.INVENTORY, InventoryType.NETWORKS, INVENTORY_NETWORKS_INDEX),
    (Module.INVENTORY, InventoryType.PACAKGES, INVENTORY_PACKAGES_INDEX),
    (Module.INVENTORY, InventoryType.PORTS, INVENTORY_PORTS_INDEX),
    (Module.INVENTORY, InventoryType.PROCESSES, INVENTORY_PROCESSES_INDEX),
    (Module.INVENTORY, InventoryType.SYSTEM, INVENTORY_SYSTEM_INDEX),
    (Module.SCA, None, SCA_INDEX),
    (Module.FIM, None, FIM_INDEX),
    (Module.VULNERABILITY, None, VULNERABILITY_INDEX),
    (Module.COMMAND, None, CommandsManager.INDEX),
])
def test_get_module_index_name(module, type, expected_name):
    """Validate that the `get_module_index_name` works as expected."""
    actual_name = get_module_index_name(module, type)

    assert actual_name == expected_name


@pytest.mark.parametrize('module, type, exception', [
    (Module.INVENTORY, 'invalid', 1763),
    ('test', 'package', 1765),
])
def test_get_module_index_name_ko(module, type, exception):
    """Validate that the `get_module_index_name` fails if the module is not valid."""
    with pytest.raises(WazuhError, match=rf'{exception}'):
        get_module_index_name(module, type)
