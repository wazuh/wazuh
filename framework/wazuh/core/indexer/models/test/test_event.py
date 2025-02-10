import pytest
from wazuh.core.exception import WazuhError
from wazuh.core.indexer.models.events import (
    FIM_INDEX,
    INVENTORY_HARDWARE_INDEX,
    INVENTORY_HOTFIXES_INDEX,
    INVENTORY_NETWORKS_INDEX,
    INVENTORY_PACKAGES_INDEX,
    INVENTORY_PORTS_INDEX,
    INVENTORY_PROCESSES_INDEX,
    INVENTORY_SYSTEM_INDEX,
    SCA_INDEX,
    VULNERABILITY_INDEX,
    Collector,
    CommandsManager,
    Module,
    get_module_index_name,
)


@pytest.mark.parametrize(
    'module, type, expected_name',
    [
        (Module.INVENTORY, Collector.HARDWARE, INVENTORY_HARDWARE_INDEX),
        (Module.INVENTORY, Collector.HOTFIXES, INVENTORY_HOTFIXES_INDEX),
        (Module.INVENTORY, Collector.NETWORKS, INVENTORY_NETWORKS_INDEX),
        (Module.INVENTORY, Collector.PACKAGES, INVENTORY_PACKAGES_INDEX),
        (Module.INVENTORY, Collector.PORTS, INVENTORY_PORTS_INDEX),
        (Module.INVENTORY, Collector.PROCESSES, INVENTORY_PROCESSES_INDEX),
        (Module.INVENTORY, Collector.SYSTEM, INVENTORY_SYSTEM_INDEX),
        (Module.SCA, None, SCA_INDEX),
        (Module.FIM, None, FIM_INDEX),
        (Module.VULNERABILITY, None, VULNERABILITY_INDEX),
        (Module.COMMAND, None, CommandsManager.INDEX),
    ],
)
def test_get_module_index_name(module, type, expected_name):
    """Validate that the `get_module_index_name` works as expected."""
    actual_name = get_module_index_name(module, type)

    assert actual_name == expected_name


@pytest.mark.parametrize(
    'module, type, exception',
    [
        (Module.INVENTORY, 'invalid', 1763),
        ('test', 'package', 1765),
    ],
)
def test_get_module_index_name_ko(module, type, exception):
    """Validate that the `get_module_index_name` fails if the module is not valid."""
    with pytest.raises(WazuhError, match=rf'{exception}'):
        get_module_index_name(module, type)
