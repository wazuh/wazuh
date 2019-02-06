#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
from unittest import TestCase
from unittest.mock import patch


from wazuh import WazuhException
from wazuh.manager import upload_file, get_file, restart

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')

class TestManager(TestCase):

    def setUp(self):
        # rules
        self.input_rules_file = os.path.join(os.getcwd(), 'tests/data/test_rules.xml')
        self.output_rules_file = os.path.join(os.getcwd(), 'tests/data/uploaded_test_rules.xml')
        # decoders
        self.input_decoders_file = os.path.join(os.getcwd(), 'tests/data/test_decoders.xml')
        self.output_decoders_file = os.path.join(os.getcwd(), 'tests/data/uploaded_test_decoders.xml')
        # CDB lists
        self.input_lists_file = os.path.join(os.getcwd(), 'tests/data/test_lists')
        self.output_lists_file = os.path.join(os.getcwd(), 'tests/data/uploaded_test_lists')

    def tearDown(self):
        regex = re.compile(r'^uploaded')
        for filename in os.listdir(os.path.join(os.getcwd(), 'tests/data')):
            if regex.match(filename):
                os.remove(os.path.join(os.getcwd(), 'tests/data', filename))

    @patch('common.ossec_path', test_data_path)
    def test_upload_file(self):
        # rules
        upload_file(self.input_rules_file, self.output_rules_file, 'application/xml')
        self.assertTrue(os.path.isfile(self.output_rules_file))
        # decoders
        upload_file(self.input_decoders_file, self.output_decoders_file, 'application/xml')
        self.assertTrue(os.path.isfile(self.output_decoders_file))
        # CDB lists
        upload_file(self.input_lists_file, self.output_lists_file, 'application/octet-stream')
        self.assertTrue(os.path.isfile(self.output_lists_file))

    @patch('common.ossec_path', test_data_path)
    def test_get_file(self):
        # rules
        result = get_file(os.path.join(os.getcwd(), 'tests/data/test_rules.xml'))
        self.assertIsInstance(result, str)
        # decoders
        result = get_file(os.path.join(os.getcwd(), 'tests/data/test_decoders.xml'))
        self.assertIsInstance(result, str)
        # CDB lists
        result = get_file(os.path.join(os.getcwd(), 'tests/data/test_lists'))
        self.assertIsInstance(result, str)

    @patch('socket.socket')
    def test_restart_ok(self, mock1):
        self.assertEqual(restart(), 'Manager is going to restart now')

    @patch('wazuh.manager.exists', return_value=False)
    def test_restart_ko_socket(self, mock1):
        with self.assertRaises(WazuhException) as cm:
            restart()

        self.assertEqual(cm.exception.code, 1901)