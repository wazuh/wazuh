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
from wazuh_testing.modules.agentd.configuration import AGENTD_DEBUG, AGENTD_WINDOWS_DEBUG
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

# Valid UTF-8 filename test cases with actual symbols, diacritics, and multi-language characters
valid_utf8_sequences= [
    "Hello_World.txt",          # Basic ASCII
    "Über.txt",          # Ü (U+00DC, 2-byte UTF-8)
    "über.txt",          # ü (U+00FC, 2-byte UTF-8)
    "☃_snowman.txt",  # ☃ (U+2603, 3-byte UTF-8)
    "😁_smile.txt",  # 😁 (U+1F601, 4-byte UTF-8)
    "Japanese_こんにちは.txt",   # Japanese text (multi-byte)
    "Korean_안녕하세요.txt",     # Korean text (multi-byte)
    "Spanish_¡Hola!.txt",       # Spanish text with diacritic (¡)
    "French_Ça_va.txt",         # French text with diacritic (Ç)
    "German_Äpfel.txt",         # German text with diacritic (Ä)
    "Portuguese_É_bom.txt",     # Portuguese text with diacritic (É)
    "Turkish_İyi_günler.txt",   # Turkish text with diacritic (İ)
    "Estonian_Õnnelik.txt",     # Estonian text with diacritic (Õ)
    "Polish_Łódź.txt",          # Polish text with diacritic (Ł)
    "Czech_Škoda.txt",          # Czech text with diacritic (Š)
    "Hungarian_Öröm.txt",       # Hungarian text with diacritic (Ö)
    "Romanian_Și.txt",          # Romanian text with diacritic (Ș)
    "Vietnamese_Đồng.txt",      # Vietnamese text with diacritic (Đ)
    "Thai_สวัสดี.txt",         # Thai text (multi-byte)
    "Tamil_வணக்கம்.txt",      # Tamil text (multi-byte)
    "Telugu_నమస్కారం.txt",   # Telugu text (multi-byte)
    "Finnish_Ääkköset.txt",     # Finnish text with diacritic (Ää)
    "Norwegian_Ålesund.txt",    # Norwegian text with diacritic (Å)
    "Greek_Σὲ_γνωρίζω.txt",     # Greek text with multi-byte sequences
    "Chinese_中文字符.txt",       # Chinese characters (3-byte UTF-8)
    "Russian_Привет.txt",       # Cyrillic characters (multi-byte)
    "Hebrew_שלום.txt",          # Hebrew text (multi-byte)
    "Arabic_مرحبا.txt",         # Arabic text (multi-byte)
    "Hindi_नमस्ते.txt",         # Hindi (Devanagari script, multi-byte)
    "Math_∑_√_π.txt",           # Mathematical symbols (sum, square root, pi)
    "Technical_±_Ω.txt",        # Technical symbols (plus-minus, ohm)
    "Emoji_🎉_🚀.txt",           # Emoji characters
    "Currency_€_¥_£.txt",       # Currency symbols (Euro, Yen, Pound)
    "Punctuation_@_#_%_&.txt",  # Various punctuation characters
    "File_with_parentheses_(example).txt",  # Parentheses in filename
]

# Invalid UTF-8 byte sequences (these should trigger warnings in logs)
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


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_valid_utf8_filenames_do_not_trigger_warning(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                                                     truncate_monitored_files, folder_to_monitor, daemons_handler, start_monitoring) -> None:
    '''
    description: Check if the 'wazuh-syscheckd' correctly processes valid UTF-8 file names without triggering warnings.
    '''
    monitor = FileMonitor(WAZUH_LOG_PATH)

    # iterate over invalid UTF-8 sequences
    for valid_sequence in valid_utf8_sequences:
        # No UTF-8 conversion here, just direct file name creation with invalid sequences
        test_path_bytes = os.path.join(
            test_metadata['folder_to_monitor'], valid_sequence)
        file.truncate_file(WAZUH_LOG_PATH)

        try:
            # Create the file with the invalid byte sequence as part of the file name
            open(test_path_bytes, 'wb').close()
        except Exception as e:
            print(
                f"Error creating file with invalid byte sequence {valid_sequence}: {e}")

        monitor.start(generate_callback(SYNC_INTEGRITY_MESSAGE))
        assert monitor.callback_result


@pytest.mark.parametrize('test_configuration, test_metadata', zip(test_configuration, test_metadata), ids=cases_ids)
def test_non_utf8_sequences_should_trigger_warning(test_configuration, test_metadata, set_wazuh_configuration, configure_local_internal_options,
                                                   truncate_monitored_files, folder_to_monitor, daemons_handler, start_monitoring) -> None:
    '''
    description: Check if the 'wazuh-syscheckd' logs a warning for non-UTF-8 sequences in file names.
    '''
    monitor = FileMonitor(WAZUH_LOG_PATH)

    # iterate over invalid UTF-8 sequences
    for invalid_sequence in maximal_cases + surrogate_boundary_sequences:
        # No UTF-8 conversion here, just direct file name creation with invalid sequences
        # Byte conversion here to concatenate with invalid sequences
        folder_to_monitor_bytes: bytes = test_metadata['folder_to_monitor'].encode(
            'utf-8')
        test_path_bytes = os.path.join(
            folder_to_monitor_bytes, invalid_sequence)
        file.truncate_file(WAZUH_LOG_PATH)

        try:
            # Create the file with the invalid byte sequence as part of the file name
            open(test_path_bytes, 'wb').close()
        except Exception as e:
            print(
                f"Error creating file with invalid byte sequence {invalid_sequence!r}: {e}")

        monitor.start(generate_callback(IGNORING_DUE_TO_INVALID_NAME))
        assert monitor.callback_result
