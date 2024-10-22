'''
copyright: Copyright (C) 2015-2024, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: File Integrity Monitoring (FIM) system watches selected files and triggering alerts when these
       files are modified. In particular, these tests will check if FIM can correctly process path names
       containing non-UTF8 characters, logging any problems encountered and treating them correctly.

components:
    - fim

suite: invalid_characters

targets:
    - agent

daemons:
    - wazuh-syscheckd

os_platform:
    - Linux
    - Windows

os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic
    - Windows 10
    - Windows Server 2019
    - Windows Server 2016

references:
    - https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/index.html
    - https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html

pytest_args:
    - fim_mode:
        realtime: Enable real-time monitoring on Linux (using the 'inotify' system calls) and Windows systems.
        whodata: Implies real-time monitoring but adding the 'who-data' information.
    - tier:
        0: Only level 0 tests are performed, they check basic functionalities and are quick to perform.
        1: Only level 1 tests are performed, they check functionalities of medium complexity.
        2: Only level 2 tests are performed, they check advanced functionalities and are slow to perform.

tags:
    - fim
'''

import os
import sys

import pytest

if sys.platform == 'win32':
    import win32con
    from win32con import KEY_WOW64_64KEY

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.constants.services import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG, MONITORD_ROTATE_LOG
from wazuh_testing.modules.fim import configuration
from wazuh_testing.modules.fim.patterns import (IGNORING_DUE_TO_INVALID_NAME,
                                                SYNC_INTEGRITY_MESSAGE)
from wazuh_testing.modules.monitord.configuration import MONITORD_ROTATE_LOG
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import file
from wazuh_testing.utils.callbacks import generate_callback
from wazuh_testing.utils.configuration import (get_test_cases_data,
                                               load_configuration_template)

from . import CONFIGS_PATH, TEST_CASES_PATH

# Pytest marks to run on any service type on linux or windows.
pytestmark = [pytest.mark.agent, pytest.mark.linux,
              pytest.mark.win32, pytest.mark.tier(level=1)]

# Test metadata, configuration and ids.
cases_path = Path(TEST_CASES_PATH, 'cases_nonUTF8.yaml')
config_path = Path(CONFIGS_PATH, 'configuration_basic.yaml')
test_configuration, test_metadata, cases_ids = get_test_cases_data(cases_path)
test_configuration = load_configuration_template(
    config_path, test_configuration, test_metadata)

# Set configurations required by the fixtures.
local_internal_options = {
    configuration.SYSCHECK_DEBUG: 2, AGENTD_DEBUG: 2, MONITORD_ROTATE_LOG: 0}
if sys.platform == WINDOWS:
    local_internal_options.update({AGENTD_WINDOWS_DEBUG: 2})


# Invalid UTF-8 byte sequences (these should trigger warnings in logs)
invalid_byte_sequences = [
    b"\xC0\xAF",           # Overlong encoding of '/'
    b"\xE0\x80\xAF",       # Overlong encoding (null character U+002F)
    b"\xED\xA0\x80",       # UTF-16 surrogate half (invalid in UTF-8)
    b"\xF8\x88\x80\x80\x80",  # 5-byte sequence (invalid in UTF-8)
    b"\xFF",               # Invalid single byte (not valid in UTF-8)
    b"\x80",               # Continuation byte without a start
    b"\xC3\x28",           # Invalid 2-byte sequence (invalid second byte)
]

# Incomplete UTF-8 sequences
incomplete_sequences = [
    b"\xC2",             # Missing second byte for 2-byte sequence
    b"\xE2\x98",         # Missing third byte for 3-byte sequence
    b"\xF0\x9F\x98",     # Missing fourth byte for 4-byte sequence
]

# Overlong encodings
overlong_sequences = [
    b"\xC0\x80",         # Overlong encoding for null character (U+0000)
    b"\xE0\x80\x80",     # Overlong encoding for null character (U+0000)
    b"\xF0\x80\x80\x80",  # Overlong encoding for null character (U+0000)
]

# Maximal valid UTF-8 cases (1-byte, 2-byte, 3-byte, and 4-byte sequences)
maximal_cases = [
    b"\x7F",             # U+007F (1 byte)
    b"\xDF\xBF",         # U+07FF (2 bytes)
    b"\xEF\xBF\xBF",     # U+FFFF (3 bytes)
    b"\xF4\x8F\xBF\xBF",  # U+10FFFF (4 bytes)
]

# Surrogate boundary cases
surrogate_boundary_sequences = [
    b"\xED\x9F\xBF",     # U+D7FF (valid)
    b"\xED\xA0\x80",     # U+D800 (invalid)
]

# Mixed valid/invalid UTF-8 sequences
mixed_valid_invalid = [
    b"valid_utf8_\xC0\xAF_invalid",  # Mixed valid/invalid sequence
    b"A\xE0\x80\xAFB",              # Valid ASCII, invalid overlong, valid ASCII
]


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_invalid_utf8_sequences(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                                truncate_monitored_files, folder_to_monitor, daemons_handler, start_monitoring):
    '''
    description: Check if the 'wazuh-syscheckd' is able to correctly detect a pathname containing an invalid
                 character, preventing its processing and writing a log warning.
    '''

    monitor = FileMonitor(WAZUH_LOG_PATH)

    # iterate over invalid UTF-8 sequences
    for invalid_sequence in invalid_byte_sequences:
        # No UTF-8 conversion here, just direct file name creation with invalid sequences
        test_path_bytes = os.path.join(
            test_metadata['folder_to_monitor'], invalid_sequence)
        file.truncate_file(WAZUH_LOG_PATH)

        try:
            # Create the file with the invalid byte sequence as part of the file name
            open(test_path_bytes, 'wb').close()
        except Exception as e:
            print(
                f"Error creating file with invalid byte sequence {invalid_sequence}: {e}")

        monitor.start(generate_callback(IGNORING_DUE_TO_INVALID_NAME))
        assert monitor.callback_result


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_incomplete_utf8_sequences(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                                   truncate_monitored_files, folder_to_monitor, daemons_handler, start_monitoring):
    '''
    description: Check if the 'wazuh-syscheckd' is able to detect incomplete UTF-8 sequences.
    '''

    monitor = FileMonitor(WAZUH_LOG_PATH)

    for sequence in incomplete_sequences:
        # Direct path with no UTF-8 conversion
        test_path_bytes = os.path.join(
            test_metadata['folder_to_monitor'], sequence)
        file.truncate_file(WAZUH_LOG_PATH)

        try:
            # Create the file with the incomplete UTF-8 sequence as part of the file name
            open(test_path_bytes, 'wb').close()
        except Exception as e:
            print(
                f"Error creating file with incomplete UTF-8 sequence {sequence}: {e}")

        monitor.start(generate_callback(IGNORING_DUE_TO_INVALID_NAME))
        assert monitor.callback_result


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_overlong_utf8_encodings(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                                 truncate_monitored_files, folder_to_monitor, daemons_handler, start_monitoring):
    '''
    description: Check if the 'wazuh-syscheckd' is able to detect overlong UTF-8 encodings.
    '''

    monitor = FileMonitor(WAZUH_LOG_PATH)

    for sequence in overlong_sequences:
        # Direct path with no UTF-8 conversion
        test_path_bytes = os.path.join(
            test_metadata['folder_to_monitor'], sequence)
        file.truncate_file(WAZUH_LOG_PATH)

        try:
            # Create the file with the overlong encoding as part of the file name
            open(test_path_bytes, 'wb').close()
        except Exception as e:
            print(
                f"Error creating file with overlong UTF-8 sequence {sequence}: {e}")

        monitor.start(generate_callback(IGNORING_DUE_TO_INVALID_NAME))
        assert monitor.callback_result


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_maximal_valid_utf8_cases(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                                  truncate_monitored_files, folder_to_monitor, daemons_handler, start_monitoring):
    '''
    description: Check if the 'wazuh-syscheckd' correctly processes maximal valid UTF-8 cases without issues.
    '''

    monitor = FileMonitor(WAZUH_LOG_PATH)

    for sequence in maximal_cases:
        # Direct path with no UTF-8 conversion
        test_path_bytes = os.path.join(
            test_metadata['folder_to_monitor'], sequence)
        file.truncate_file(WAZUH_LOG_PATH)

        try:
            # Create the file with the maximal valid UTF-8 sequence as part of the file name
            open(test_path_bytes, 'wb').close()
        except Exception as e:
            print(
                f"Error creating file with maximal valid UTF-8 sequence {sequence}: {e}")

        monitor.start(generate_callback(SYNC_INTEGRITY_MESSAGE))
        assert monitor.callback_result


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_surrogate_pair_boundary(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                                 truncate_monitored_files, folder_to_monitor, daemons_handler, start_monitoring):
    '''
    description: Check if the 'wazuh-syscheckd' detects surrogate pair boundaries correctly.
    '''

    monitor = FileMonitor(WAZUH_LOG_PATH)

    for sequence in surrogate_boundary_sequences:
        # Direct path with no UTF-8 conversion
        test_path_bytes = os.path.join(
            test_metadata['folder_to_monitor'], sequence)
        file.truncate_file(WAZUH_LOG_PATH)

        try:
            # Create the file with the surrogate boundary sequence as part of the file name
            open(test_path_bytes, 'wb').close()
        except Exception as e:
            print(
                f"Error creating file with surrogate boundary sequence {sequence}: {e}")

        monitor.start(generate_callback(IGNORING_DUE_TO_INVALID_NAME))
        assert monitor.callback_result


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_mixed_valid_invalid_utf8(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                                  truncate_monitored_files, folder_to_monitor, daemons_handler, start_monitoring):
    '''
    description: Check if the 'wazuh-syscheckd' handles mixed valid/invalid UTF-8 sequences.
    '''

    monitor = FileMonitor(WAZUH_LOG_PATH)

    for sequence in mixed_valid_invalid:
        # Direct path with no UTF-8 conversion
        test_path_bytes = os.path.join(
            test_metadata['folder_to_monitor'], sequence)
        file.truncate_file(WAZUH_LOG_PATH)

        try:
            # Create the file with the mixed valid/invalid UTF-8 sequence as part of the file name
            open(test_path_bytes, 'wb').close()
        except Exception as e:
            print(
                f"Error creating file with mixed valid/invalid UTF-8 sequence {sequence}: {e}")

        monitor.start(generate_callback(IGNORING_DUE_TO_INVALID_NAME))
        assert monitor.callback_result
