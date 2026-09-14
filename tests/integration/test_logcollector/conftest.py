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
from wazuh_testing.utils import callbacks, configuration
from wazuh_testing.utils.services import control_service
from wazuh_testing.utils.file import truncate_file, replace_regex_in_file, write_json_file

# Logcollector internal paths
LOGCOLLECTOR_OFE_PATH = path_join(WAZUH_PATH, 'queue', 'logcollector', 'file_status.json')


@pytest.fixture(scope="module", autouse=True)
def set_agent_config():
    """Write the manager endpoint and TLS opt-out directly into the installed ossec.conf,
    once per module, before any test's own set_wazuh_configuration runs.

    This does NOT go through each test's own `test_configuration["sections"]`: several
    logcollector test files (test_basic_configuration_alias.py, _command.py, _location.py,
    _label.py, _out_format.py, _target.py) call
    validate_test_config_with_module_config(test_configuration), which queries
    `getconfig <section>` on logcollector's own control socket for every section listed
    there and raises if logcollector doesn't recognize it -- 'agent' isn't one of
    logcollector's own sections ('localfile', 'socket'), so it would fail there even though
    the opt-out has nothing to do with what those tests are actually validating.

    set_wazuh_configuration() (tests/integration/conftest.py) backs up and restores the
    whole file around each test, and re-reads the current file as its own template when
    passed no explicit one, so a section written here before the first test survives every
    later per-test backup/restore/reapply cycle in the module untouched.
    """
    # <agent> is the 5.x name for what 4.x spelled <client> (#38103). <endpoint> carries the
    # whole target -- host, port and path (#38624) -- which is why <address> and <port> are no
    # longer written here: they are the deprecated spelling and are ignored outright whenever
    # <endpoint> is present.
    agent_conf = {
        "section": "agent",
        "elements": [
            {
                "manager": {
                    "elements": [
                        {"endpoint": {"value": "127.0.0.1:1517"}},
                    ]
                }
            },
            {
                # #38956: the agent's default verification_mode is now 'system', which
                # RemotedSimulator's self-signed cert fails -- opt out explicitly since this
                # suite is not testing TLS trust.
                "ssl": {
                    "elements": [
                        {"verification_mode": {"value": "none"}},
                    ]
                }
            },
        ],
    }

    configuration.write_wazuh_conf(configuration.set_section_wazuh_conf([agent_conf]))


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
    """Reset the status file of the logcollector only future events."""

    def get_journal_last_log_timestamp():
        '''
        Get the timestamp of the last log message in the journal.

        Returns:
            int: The timestamp of the last log message in the journal.
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

    def get_ofe_journald():
        '''
        Get the status of the logcollector for journald.

        Set the timestamp of the last log message in the journal as the timestamp for the journald.
        if the test_metadata contains the key 'force_timestamp', the value of this key will be used as the timestamp.

        Returns:
            dict: The status of the logcollector for journald.
        '''

        if 'force_timestamp' in test_metadata:
            epoch_timestamp = test_metadata['force_timestamp']
        else:
            epoch_timestamp = get_journal_last_log_timestamp()

        status: dict = { "timestamp": str(epoch_timestamp) }
        return status
        
    # File status for logcollector
    file_status: dict = {}

    # Configure the file status for each logreader
    file_status['journald'] = get_ofe_journald()
    
    # Write the file status
    write_json_file(LOGCOLLECTOR_OFE_PATH, file_status)

@pytest.fixture()
def pre_send_journal_logs(request: pytest.FixtureRequest, test_metadata: dict):
    """Send log messages to the journal before starting the logcollector."""
    from utils import send_log_to_journal

    if 'pre_input_logs' not in test_metadata:
        raise Exception(f"The test_metadata does not contain the key 'pre_input_logs'")
    else:
        for log_message in test_metadata['pre_input_logs']:
            send_log_to_journal(log_message)
