# Copyright (C) 2015-2024, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import shutil
from pathlib import Path

from wazuh_testing.constants.paths.configurations import CUSTOM_DECODERS_FILE, CUSTOM_RULES_FILE
from . import TEST_RULES_DECODERS_PATH

@pytest.fixture()
def setup_local_rules(test_metadata):
    if 'local_rules' in test_metadata:
        # save current rules
        shutil.copy(CUSTOM_RULES_FILE,
                    CUSTOM_RULES_FILE + '.cpy')

        file_test = test_metadata['local_rules']
        # copy test rules
        shutil.copy(Path(TEST_RULES_DECODERS_PATH, file_test), CUSTOM_RULES_FILE)
        shutil.chown(CUSTOM_RULES_FILE, "wazuh", "wazuh")

    yield

    if 'local_rules' in test_metadata:
        # restore previous rules
        shutil.move(CUSTOM_RULES_FILE + '.cpy',
                    CUSTOM_RULES_FILE)
        shutil.chown(CUSTOM_RULES_FILE, "wazuh", "wazuh")


@pytest.fixture()
def setup_local_decoders(test_metadata):
    if 'local_decoders' in test_metadata:
        # save current decoders
        shutil.copy(CUSTOM_DECODERS_FILE,
                    CUSTOM_DECODERS_FILE + '.cpy')

        file_test = test_metadata['local_decoders']
        # copy test decoder
        shutil.copy(Path(TEST_RULES_DECODERS_PATH, file_test), CUSTOM_DECODERS_FILE)
        shutil.chown(CUSTOM_DECODERS_FILE, "wazuh", "wazuh")

    yield

    if 'local_decoders' in test_metadata:
        # restore previous decoders
        shutil.move(CUSTOM_DECODERS_FILE + '.cpy',
                    CUSTOM_DECODERS_FILE)
        shutil.chown(CUSTOM_DECODERS_FILE, "wazuh", "wazuh")
