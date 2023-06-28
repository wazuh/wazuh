import pytest

from wazuh_testing.constants.paths.configurations import AR_CONF
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.agentd.patterns import AGENTD_CONNECTED_TO_SERVER
from wazuh_testing.modules.execd.patterns import EXECD_RECEIVED_MESSAGE
from wazuh_testing.tools.file_monitor import FileMonitor
from wazuh_testing.tools.simulators import RemotedSimulator
from wazuh_testing.utils import file
from wazuh_testing.utils.callbacks import generate_callback


@pytest.fixture()
def configure_ar_conf(request: pytest.FixtureRequest) -> None:
    # This fixture needs ar_conf to be declared.
    if not hasattr(request.module, 'ar_conf'):
        raise AttributeError('The var `ar_conf` is not defined in module.')

    # Get the configuration values.
    ar_config = getattr(request.module, 'ar_conf')
    # Backup the ar.conf file to restore it later.
    ar_conf_exists = file.exists_and_is_file(AR_CONF)

    if ar_conf_exists:
        backup = file.read_file_lines(AR_CONF)

    # Write new Active Response configuration.
    file.write_file(AR_CONF, ar_config)

    yield

    # Restore the ar.conf file previous state.
    if ar_conf_exists:
        file.write_file(AR_CONF, backup)
    else:
        file.delete_file(AR_CONF)


@pytest.fixture()
def send_execd_message(test_metadata: dict) -> None:
    # Validate the input to get the message from exists.
    if not test_metadata.get('input'):
        raise AttributeError('No `input` key in `test_metadata`.')
    
    # Instanciate the monitor and remoted simulator.
    remoted = RemotedSimulator()
    monitor = FileMonitor(WAZUH_LOG_PATH)

    # Start and wait for agent to connect to remoted simulator.
    remoted.start()
    monitor.start(callback=generate_callback(AGENTD_CONNECTED_TO_SERVER))

    # Once the agent is 'connected' send the input.
    remoted.send_custom_message(test_metadata['input'])
    # Wait for execd to start.
    monitor.start(callback=generate_callback(EXECD_RECEIVED_MESSAGE))

    yield
    # Turn off the simulator.
    remoted.shutdown()
