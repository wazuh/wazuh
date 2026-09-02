# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import sys
import time
import pytest

from pathlib import Path

from wazuh_testing.constants.paths.logs import WAZUH_LOG_PATH
from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.logger import logger
from wazuh_testing.modules.fim.patterns import EVENT_TYPE_ADDED, PATH_MONITORED_REALTIME
from wazuh_testing.tools.monitors.file_monitor import FileMonitor
from wazuh_testing.utils import file
from wazuh_testing.utils.callbacks import generate_callback


@pytest.fixture()
def path_to_edit(test_metadata: dict) -> str:
    to_edit = test_metadata.get('path_to_edit')
    is_directory = test_metadata.get('is_directory')

    fim_mode = test_metadata.get('fim_mode', '')
    if sys.platform == WINDOWS and fim_mode == 'realtime':
        FileMonitor(WAZUH_LOG_PATH).start(
            callback=generate_callback(PATH_MONITORED_REALTIME),
            timeout=60
        )

    if is_directory:
        file.recursive_directory_creation(to_edit)
        if sys.platform == WINDOWS:
            time.sleep(5)
        file.write_file(Path(to_edit, 'newfile'), 'test')
    else:
        file.write_file(to_edit, 'test')

    FileMonitor(WAZUH_LOG_PATH).start(generate_callback(EVENT_TYPE_ADDED))

    yield to_edit

    # test_rename.py and test_move.py -- the only two consumers of this fixture -- relocate
    # to_edit into folder_to_monitor before teardown runs, so this retry is a defensive no-op
    # for them today; folder_to_monitor's own teardown is what actually covers the relocated
    # content. Kept here in case a future test uses this fixture without relocating first.
    if sys.platform == WINDOWS:
        max_retries = 15
        retry_delay = 1
        for attempt in range(max_retries):
            try:
                file.delete_path_recursively(to_edit)
                break
            except OSError as exception:
                if attempt == max_retries - 1:
                    raise
                logger.debug(f"Retrying deletion of {to_edit}: {exception}")
                time.sleep(retry_delay)
    else:
        file.delete_path_recursively(to_edit)
