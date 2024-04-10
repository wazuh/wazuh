'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
'''
import pytest

from os.path import join as path_join

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.constants.paths.configurations import WAZUH_CONF_PATH
from wazuh_testing.constants.daemons import LOGCOLLECTOR_DAEMON
from wazuh_testing.modules.logcollector.patterns import LOGCOLLECTOR_MODULE_START
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import callbacks
from wazuh_testing.utils.services import control_service
from wazuh_testing.utils.file import truncate_file, replace_regex_in_file, write_json_file
from wazuh_testing.utils import configuration

# Logcollector internal paths
LOGCOLLECTOR_OFE_PATH = path_join(WAZUH_PATH, 'queue', 'logcollector', 'file_status.json')

@pytest.fixture()
def stop_logcollector(request):
    """Stop wazuh-logcollector and truncate logs file."""
    control_service('stop', daemon=LOGCOLLECTOR_DAEMON)
    truncate_file(WAZUH_LOG_PATH)


@pytest.fixture()
def wait_for_logcollector_start(request):
    # Wait for logcollector thread to start
    log_monitor = FileMonitor(WAZUH_LOG_PATH)
    log_monitor.start(callback=callbacks.generate_callback(LOGCOLLECTOR_MODULE_START))
    assert (log_monitor.callback_result != None), f'Error logcollector start event not detected'

@pytest.fixture()
def remove_all_localfiles_wazuh_config(request):
    """Configure a custom settting for testing. Restart Wazuh is needed for applying the configuration. """
    # Backup the original configuration
    backup_config = configuration.get_wazuh_conf()

    # Remove localfiles from the configuration
    list_tags = [r"<localfile>[\s\S]*?<\/localfile>"]
    replace_regex_in_file(list_tags, [''] * len(list_tags), WAZUH_CONF_PATH, True)

    yield
    configuration.write_wazuh_conf(backup_config)


@pytest.fixture()
def reset_ofe_status(request: pytest.FixtureRequest, test_metadata: dict):
    """Reset the status of the logcollector only future events."""


    # Get the _SOURCE_REALTIME_TIMESTAMP from the last log message in the journal
    def get_last_log_timestamp():
        '''
        Get the timestamp of the last log message in the journal.

        Returns:
            str: Timestamp of the last log message.
        '''
        from subprocess import Popen, PIPE
        from shlex import split

        # Get the last log message in the journal
        command = 'journalctl -o json -n1'
        process = Popen(split(command), stdout=PIPE, stderr=PIPE)
        output, error = process.communicate()

        if error:
            raise Exception(f"Error getting the last log message from the journal: {error.decode()}")

        # Get the timestamp of the last log message
        import json
        log_message = json.loads(output.decode())
        return log_message.get('_SOURCE_REALTIME_TIMESTAMP')

    # Set the timestamp for last read log in the logcollector configuration
    def set_ofe_timestamp_journald_logcollector():
        '''
        Set the timestamp for last read log in the logcollector file status (only future events).
        '''

        if 'force_timestamp' in test_metadata:
            epoch_timestamp = test_metadata['force_timestamp']
        else:
            # get epoch timestamp for the last log message in the journal
            epoch_timestamp = get_last_log_timestamp()

        # update the timestamp in the logcollector file status
        file_status: dict = {
            "journald": {
                "timestamp": str(epoch_timestamp)
            }
        }
        write_json_file(LOGCOLLECTOR_OFE_PATH, file_status)

    set_ofe_timestamp_journald_logcollector()

@pytest.fixture()
def pre_send_journal_logs(request: pytest.FixtureRequest, test_metadata: dict):
    """Send log messages to the journal before starting the logcollector."""
    from utils import send_log_to_journal

    if 'pre_input_logs' not in test_metadata:
        raise Exception(f"Log messages not found in the test metadata.")
    else:
        for log_message in test_metadata['pre_input_logs']:
            send_log_to_journal(log_message)
