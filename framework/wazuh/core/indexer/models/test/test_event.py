import pytest

from wazuh.core.exception import WazuhError
from wazuh.core.indexer.models.events import get_module_index_name, Module, ModuleName, FIM_INDEX, SCA_INDEX, \
    VULNERABILITY_INDEX, INVENTORY_NETWORK_INDEX, INVENTORY_PACKAGES_INDEX, INVENTORY_PROCESSES_INDEX, \
    INVENTORY_SYSTEM_INDEX, INVENTORY_NETWORK_TYPE, INVENTORY_PACKAGES_TYPE, INVENTORY_PROCESSES_TYPE, \
    INVENTORY_SYSTEM_TYPE, CommandsManager


@pytest.mark.parametrize('module, expected_name', [
    (Module(name=ModuleName.INVENTORY, type=INVENTORY_NETWORK_TYPE), INVENTORY_NETWORK_INDEX),
    (Module(name=ModuleName.INVENTORY, type=INVENTORY_PACKAGES_TYPE), INVENTORY_PACKAGES_INDEX),
    (Module(name=ModuleName.INVENTORY, type=INVENTORY_PROCESSES_TYPE), INVENTORY_PROCESSES_INDEX),
    (Module(name=ModuleName.INVENTORY, type=INVENTORY_SYSTEM_TYPE), INVENTORY_SYSTEM_INDEX),
    (Module(name=ModuleName.SCA), SCA_INDEX),
    (Module(name=ModuleName.FIM), FIM_INDEX),
    (Module(name=ModuleName.VULNERABILITY), VULNERABILITY_INDEX),
    (Module(name=ModuleName.COMMAND), CommandsManager.INDEX),
])
def test_get_module_index_name(module, expected_name):
    """Validate that the `get_module_index_name` works as expected."""
    actual_name = get_module_index_name(module)

    assert actual_name == expected_name


@pytest.mark.parametrize('name, type, exception', [
    (ModuleName.INVENTORY, 'invalid', 1763),
    ('test', 'package', 1765),
])
def test_get_module_index_name_ko(name, type, exception):
    """Validate that the `get_module_index_name` fails if the module is not valid."""
    module = Module(name=name, type=type)
    with pytest.raises(WazuhError, match=rf'{exception}'):
        get_module_index_name(module)
