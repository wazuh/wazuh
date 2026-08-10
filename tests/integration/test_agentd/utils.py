# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.agentd.patterns import *
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import callbacks


def wait_keepalive():
    """
        Watch ossec.log until "Sending keep alive" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(AGENTD_SENDING_KEEP_ALIVE), timeout = 100)
    assert (wazuh_log_monitor.callback_result != None), f'Sending keep alive not found'


def wait_connect():
    """
        Watch ossec.log until the agent connects to the server -- either the legacy TCP
        "Connected to the server" line, or the HTTPS client's "startup accepted" milestone
        (wazuh/wazuh#37831; both paths run side by side during the migration).
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    connected_pattern = fr'({AGENTD_CONNECTED_TO_SERVER}|{AGENTD_HTTPS_STARTUP_ACCEPTED})'
    wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(connected_pattern), timeout = 150)
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


def wait_enrollment_try():
    """
        Watch ossec.log until "Requesting a key" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(AGENTD_REQUESTING_KEY,{'IP':''}), timeout = 150)
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
    wazuh_log_monitor.start(callback=callbacks.generate_callback(AGENTD_UNABLE_TO_CONNECT_TO_ANY), timeout = 120)
    assert (wazuh_log_monitor.callback_result != None), f'Unable to connect to any server message not found'


def check_connection_try():
    """
        Watch ossec.log until "Trying to connect to server" message is found
    """
    wazuh_log_monitor = FileMonitor(WAZUH_LOG_PATH)
    matched_line = wazuh_log_monitor.start(only_new_events = True, callback=callbacks.generate_callback(AGENTD_TRYING_CONNECT,{'IP':'','PORT':''}), return_matched_line = True)
    assert (wazuh_log_monitor.callback_result != None), f'Trying to connect to server message not found'
    return matched_line
