from datetime import datetime

from wazuh_testing.constants.paths.configurations import WAZUH_CLIENT_KEYS_PATH
from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.agentd.patterns import * 
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import callbacks

def add_custom_key() -> None:
    """Set test client.keys file"""
    with open(WAZUH_CLIENT_KEYS_PATH, 'w+') as client_keys:
        client_keys.write("100 ubuntu-agent any TopSecret")

def kill_server(server):
    if server:
        server.clear()
        server.shutdown()

def parse_time_from_log_line(log_line):
    """Create a datetime object from a date in a string.

    Args:
        log_line (str): String with date.

    Returns:
        datetime: datetime object with the parsed time.
    """
    data = log_line.split(" ")
    (year, month, day) = data[0].split("/")
    (hour, minute, second) = data[1].split(":")
    log_time = datetime(year=int(year), month=int(month), day=int(day), hour=int(hour), minute=int(minute),
                        second=int(second))
    return log_time

def get_regex(pattern, server_address, server_port):
    if(pattern == 'AGENTD_TRYING_CONNECT'):
        regex = globals()[pattern]
        values = {'IP': str(server_address), 'PORT':str(server_port)}
    elif (pattern == 'AGENTD_REQUESTING_KEY'):
        regex = globals()[pattern]
        values = {'IP': str(server_address)}
    elif (pattern == 'AGENTD_CONNECTED_TO_ENROLLMENT'):
        regex = globals()[pattern]
        values = {'IP': '', 'PORT': ''}
    elif (pattern == 'AGENTD_RECEIVED_VALID_KEY' or pattern == 'AGENTD_RECEIVED_ACK' or 
          pattern == 'AGENTD_SERVER_RESPONDED' or pattern == 'AGENTD_RECEIVED_ACK'):
        regex = globals()[pattern]
        values = {}
    return regex, values

def wait_keepalive():
    """
        Watch ossec.log until "Sending keep alive" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(AGENTD_SENDING_KEEP_ALIVE))
    assert (wazuh_log_monitor.callback_result != None), f'Sending keep alive not found'

def wait_connect():
    """
        Watch ossec.log until received "Connected to the server" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(AGENTD_CONNECTED_TO_SERVER))
    assert (wazuh_log_monitor.callback_result != None), f'Connected to the server message not found'

def wait_ack():
    """
        Watch ossec.log until "Received ack message" is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(AGENTD_RECEIVED_ACK))
    assert (wazuh_log_monitor.callback_result != None), f'Received ack message not found'

def wait_state_update():
    """
        Watch ossec.log until "Updating state file" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(AGENTD_UPDATING_STATE_FILE))
    assert (wazuh_log_monitor.callback_result != None), f'State file update not found'

def wait_enrollment():
    """
        Watch ossec.log until "Valid key received" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(AGENTD_RECEIVED_VALID_KEY))
    assert (wazuh_log_monitor.callback_result != None), 'Agent never enrolled'

def wait_enrollment_try():
    """
        Watch ossec.log until "Requesting a key" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(AGENTD_REQUESTING_KEY), timeout = 50)
    assert (wazuh_log_monitor.callback_result != None), f'Enrollment retry was not sent'

def wait_agent_notification(current_value):
    """
        Watch ossec.log until "Sending agent notification" message is found current_value times
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(AGENTD_SENDING_AGENT_NOTIFICATION), accumulations = int(current_value))
    assert (wazuh_log_monitor.callback_result != None), f'Sending agent notification message not found'

def wait_server_rollback():
    """
        Watch ossec.log until "Unable to connect to any server" message is found'
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(AGENTD_UNABLE_TO_CONNECT))
    assert (wazuh_log_monitor.callback_result != None), f'Unable to connect to any server message not found'

def check_module_stop():
    """
        Watch ossec.log until "Unable to access queue" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(callback=callbacks.generate_callback(AGENTD_MODULE_STOPPED))
    assert (wazuh_log_monitor.callback_result == None), f'Unable to access queue message found'

def check_connection_try():
    """
        Watch ossec.log until "Trying to connect to server" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    matched_line = wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(AGENTD_TRYING_CONNECT), return_matched_line = True)
    assert (wazuh_log_monitor.callback_result != None), f'Trying to connect to server message not found'
    return matched_line
