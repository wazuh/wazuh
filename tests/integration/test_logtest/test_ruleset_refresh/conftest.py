# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import os
from shutil import copy

from wazuh_testing.constants.paths import WAZUH_PATH
from . import TEST_RULES_DECODERS_PATH

@pytest.fixture(scope='function')
def configure_rules_list(test_metadata):
    """Configure a custom rules and log alert level for testing.
    Restarting Wazuh is not needed for applying the configuration, it is optional.
    """

    # configuration for testing
    rules_dir = os.path.join(WAZUH_PATH, test_metadata['rule_dir'])
    if not os.path.exists(rules_dir):
        os.makedirs(rules_dir)

    file_test = os.path.join(TEST_RULES_DECODERS_PATH, test_metadata['rule_file'])
    file_dst = os.path.join(rules_dir, test_metadata['rule_file'])

    copy(file_test, file_dst)

    yield

    # restore previous configuration
    os.remove(file_dst)
    if len(os.listdir(rules_dir)) == 0:
        os.rmdir(rules_dir)


@pytest.fixture(scope='function')
def configure_cdbs_list(test_metadata):
    """Configure a custom cdbs for testing.

    Restarting Wazuh is not needed for applying the configuration, it is optional.
    """

    # cdb configuration for testing
    cdb_dir = os.path.join(WAZUH_PATH, test_metadata['cdb_dir'])
    if not os.path.exists(cdb_dir):
        os.makedirs(cdb_dir)

    file_cdb_test = os.path.join(TEST_RULES_DECODERS_PATH, test_metadata['cdb_file'])
    file_cdb_dst = os.path.join(cdb_dir, test_metadata['cdb_file'])

    copy(file_cdb_test, file_cdb_dst)

    # rule configuration for testing
    rule_dir = os.path.join(WAZUH_PATH, test_metadata['rule_dir'])
    if not os.path.exists(rule_dir):
        os.makedirs(rule_dir)

    file_rule_test = os.path.join(TEST_RULES_DECODERS_PATH, test_metadata['rule_file'])
    file_rule_dst = os.path.join(rule_dir, test_metadata['rule_file'])

    copy(file_rule_test, file_rule_dst)

    yield

    # restore previous configuration
    os.remove(file_cdb_dst)
    if len(os.listdir(cdb_dir)) == 0:
        os.rmdir(cdb_dir)
    os.remove(file_rule_dst)
    if len(os.listdir(rule_dir)) == 0:
        os.rmdir(rule_dir)


@pytest.fixture(scope='function')
def configure_decoders_list(test_metadata):
    """Configure a custom decoder in local_decoder.xml for testing.

    Restarting Wazuh is needed for applying the configuration, it is optional.
    """

    # configuration for testing
    decode_dir = os.path.join(WAZUH_PATH, test_metadata['decoder_dir'])
    if not os.path.exists(decode_dir):
        os.makedirs(decode_dir)

    file_test = os.path.join(TEST_RULES_DECODERS_PATH, test_metadata['decoder_file'])
    file_dst = os.path.join(decode_dir, test_metadata['decoder_file'])

    copy(file_test, file_dst)

    yield

    # restore previous configuration
    os.remove(file_dst)
    if len(os.listdir(decode_dir)) == 0:
        os.rmdir(decode_dir)
