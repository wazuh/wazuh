# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
from pathlib import Path
import shutil

from wazuh_testing.constants import users
from wazuh_testing.constants.paths import ruleset
from . import TEST_RULES_PATH


@pytest.fixture(scope='function')
def configure_rules_list(test_metadata):
    """Configure a custom rules for testing.

    Restart Wazuh is not needed for applying the configuration, is optional.
    """

    # save current rules
    shutil.copy(ruleset.LOCAL_RULES_PATH, ruleset.LOCAL_RULES_PATH + '.cpy')

    file_test = Path(TEST_RULES_PATH, test_metadata['rule_file'])
    # copy test rules
    shutil.copy(file_test, ruleset.LOCAL_RULES_PATH)
    shutil.chown(ruleset.LOCAL_RULES_PATH, users.WAZUH_UNIX_USER, users.WAZUH_UNIX_GROUP)

    yield

    # restore previous configuration
    shutil.move(ruleset.LOCAL_RULES_PATH + '.cpy', ruleset.LOCAL_RULES_PATH)
    shutil.chown(ruleset.LOCAL_RULES_PATH, users.WAZUH_UNIX_USER, users.WAZUH_UNIX_GROUP)
