# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
from os import remove
from pathlib import Path
from shutil import copy

from wazuh_testing.constants.paths.ruleset import CUSTOM_DECODERS_PATH
from wazuh_testing.constants.paths.ruleset import CUSTOM_RULES_PATH
from . import TEST_RULES_DECODERS_PATH, TEST_RULES_DECODERS_PATH


@pytest.fixture(scope='function')
def configure_local_decoders(test_metadata):
    """Configure a custom decoder for testing."""

    # configuration for testing
    file_test = Path(TEST_RULES_DECODERS_PATH, test_metadata['decoder'])
    target_file_test = Path(CUSTOM_DECODERS_PATH, test_metadata['decoder'])

    copy(file_test, target_file_test)

    yield

    # restore previous configuration
    remove(target_file_test)


@pytest.fixture(scope='function')
def configure_local_rules(test_metadata):
    """Configure a custom rule in local_rules.xml for testing."""

    # configuration for testing
    file_test = Path(TEST_RULES_DECODERS_PATH, test_metadata['rules'])
    target_file_test = Path(CUSTOM_RULES_PATH, test_metadata['rules'])
    copy(file_test, target_file_test)

    yield

    # remove configuration
    remove(target_file_test)