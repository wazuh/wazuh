# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import pytest
import shutil
from pathlib import Path

from . import TEST_RULES_DECODERS_PATH

@pytest.fixture()
def setup_local_rules(test_metadata):
    if 'local_rules' in test_metadata:
        # save current rules
        shutil.copy('/var/ossec/etc/rules/local_rules.xml',
                    '/var/ossec/etc/rules/local_rules.xml.cpy')

        file_test = test_metadata['local_rules']
        # copy test rules
        shutil.copy(Path(TEST_RULES_DECODERS_PATH, file_test), '/var/ossec/etc/rules/local_rules.xml')
        shutil.chown('/var/ossec/etc/rules/local_rules.xml', "wazuh", "wazuh")

    yield

    if 'local_rules' in test_metadata:
        # restore previous rules
        shutil.move('/var/ossec/etc/rules/local_rules.xml.cpy',
                    '/var/ossec/etc/rules/local_rules.xml')
    shutil.chown('/var/ossec/etc/rules/local_rules.xml', "wazuh", "wazuh")


@pytest.fixture()
def setup_local_decoders(test_metadata):
    if 'local_decoders' in test_metadata:
        # save current decoders
        shutil.copy('/var/ossec/etc/decoders/local_decoder.xml',
                    '/var/ossec/etc/decoders/local_decoder.xml.cpy')

        file_test = test_metadata['local_decoders']
        # copy test decoder
        shutil.copy(Path(TEST_RULES_DECODERS_PATH, file_test), '/var/ossec/etc/decoders/local_decoder.xml')
        shutil.chown('/var/ossec/etc/decoders/local_decoder.xml', "wazuh", "wazuh")

    yield

    if 'local_decoders' in test_metadata:
        # restore previous decoders
        shutil.move('/var/ossec/etc/decoders/local_decoder.xml.cpy',
                    '/var/ossec/etc/decoders/local_decoder.xml')
        shutil.chown('/var/ossec/etc/decoders/local_decoder.xml', "wazuh", "wazuh")
