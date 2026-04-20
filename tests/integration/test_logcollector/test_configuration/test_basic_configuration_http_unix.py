'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: Validate the runtime configuration exposed by Logcollector when an http-unix localfile is configured.

components:
    - logcollector

suite: configuration

targets:
    - agent

daemons:
    - wazuh-logcollector
    - wazuh-manager-apid

os_platform:
    - linux

tags:
    - logcollector_configuration
'''

import os
import tempfile
import pytest

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.modules.logcollector import utils as logcollector_utils
from wazuh_testing.tools.monitors import file_monitor
from wazuh_testing.utils import callbacks

from utils import build_tc_config


pytestmark = [pytest.mark.agent, pytest.mark.linux, pytest.mark.tier(level=0)]

socket_path = os.path.join(tempfile.gettempdir(), 'wazuh-itest-http-unix-cfg.sock')

test_configuration = build_tc_config([
    [
        [
            {'location': {'value': socket_path}},
            {'log_format': {'value': 'http-unix'}},
            {'endpoint': {'value': '/events'}},
            {'reconnect_interval': {'value': '15'}},
            {'target': {'value': 'agent'}},
            {'age': {'value': '5m'}}
        ]
    ]
])

test_metadata = [{'socket_path': socket_path}]

local_internal_options = {
    'logcollector.debug': '2',
    'logcollector.vcheck_files': '1'
}

daemons_handler_configuration = {'all_daemons': True}


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=['http-unix-runtime-config'])
def test_configuration_http_unix(test_configuration, test_metadata, truncate_monitored_files, configure_local_internal_options,
                                 remove_all_localfiles_wazuh_config, set_wazuh_configuration, daemons_handler,
                                 wait_for_logcollector_start):
    '''Verify the http-unix log_format is parsed, defaults applied, incompatible options ignored,
    and the runtime configuration exposes the http-unix-specific fields.'''
    logcollector_utils.check_logcollector_socket()

    monitor = file_monitor.FileMonitor(WAZUH_LOG_PATH)
    monitor.start(
        callback=callbacks.generate_callback(r".*log_format 'http-unix' does not support 'age' option."),
        timeout=10
    )
    assert monitor.callback_result is not None, 'The ignored age warning was not generated.'

    localfile_list = logcollector_utils.get_localfile_runtime_configuration()

    assert len(localfile_list) == 1
    assert localfile_list[0]['logformat'] == 'http-unix'
    assert localfile_list[0]['file'] == test_metadata['socket_path']
    assert localfile_list[0]['target'] == ['agent']
    assert localfile_list[0]['endpoint'] == '/events'
    assert localfile_list[0]['reconnect_interval'] == 15
    assert 'age' not in localfile_list[0]
    assert 'only-future-events' not in localfile_list[0]
