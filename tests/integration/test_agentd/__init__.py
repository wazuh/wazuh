import os
import time

from wazuh_testing.constants.paths.configurations import WAZUH_CLIENT_KEYS_PATH
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.agentd.patterns import * 
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import callbacks

def add_custom_key() -> None:
    """Set test client.keys file"""
    with open(WAZUH_CLIENT_KEYS_PATH, 'w+') as client_keys:
        client_keys.write("100 ubuntu-agent any TopSecret")

def wait_keepalive():
    """
        Watch ossec.log until "Sending keep alive" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(AGENTD_SENDING_KEEP_ALIVE))
    truncate_wazuh_logs()
    assert (wazuh_log_monitor.callback_result != None), f'Sending keep alive not found'

def wait_connect():
    """
        Watch ossec.log until received "Connected to the server" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(AGENTD_CONNECTED_TO_SERVER))
    truncate_wazuh_logs()
    assert (wazuh_log_monitor.callback_result != None), f'Connected to the server message not found'

def wait_ack():
    """
        Watch ossec.log until received ack message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(AGENTD_RECEIVED_ACK))
    truncate_wazuh_logs()
    assert (wazuh_log_monitor.callback_result != None), f'Received ack message not found'

def wait_state_update():
    """
        Watch ossec.log until "Updating state file" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(AGENTD_UPDATING_STATE_FILE))
    truncate_wazuh_logs()
    assert (wazuh_log_monitor.callback_result != None), f'State file update not found'

def wait_enrollment():
    """
        Watch ossec.log until "Valid key received" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(AGENTD_RECEIVED_VALID_KEY))
    truncate_wazuh_logs()
    assert (wazuh_log_monitor.callback_result != None), 'Agent never enrolled'

def wait_enrollment_try():
    """
        Watch ossec.log until "Requesting a key" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(AGENTD_REQUESTING_KEY), timeout = 50)
    truncate_wazuh_logs()
    assert (wazuh_log_monitor.callback_result != None), f'Enrollment retry was not sent'

def wait_agent_notification(current_value):
    """
        Watch ossec.log until "Sending agent notification" message is found current_value times
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(AGENTD_SENDING_AGENT_NOTIFICATION), accumulations = int(current_value))
    truncate_wazuh_logs()
    return(wazuh_log_monitor.callback_result != None), f'Sending agent notification message not found'

def wait_server_rollback():
    """
        Watch ossec.log until "Unable to connect to any server" message is found current_value times
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(AGENTD_UNABLE_TO_CONNECT))
    truncate_wazuh_logs()
    return(wazuh_log_monitor.callback_result != None), f'Unable to connect to any server message not found'

def delete_keys_file():
    """Remove the agent's client.keys file."""
    os.remove(WAZUH_CLIENT_KEYS_PATH)
    time.sleep(1)

def check_module_stop():
    """
        Watch ossec.log until "Unable to access queue" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(AGENTD_MODULE_STOPPED))
    truncate_wazuh_logs()
    return(wazuh_log_monitor.callback_result == None), f'Unable to access queue message found'

def truncate_wazuh_logs():
    """
    Truncate a file to reset its content.

    Args:
        file_path (str): Path of the file to be truncated.
    """
    with open(WAZUH_LOG_PATH, 'w'):
        pass

def kill_server(server):
    if server:
        server.clear()
        server.shutdown()
