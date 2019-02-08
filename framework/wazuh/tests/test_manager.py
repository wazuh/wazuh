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

    @patch('socket.socket')
    def test_restart_ok(self, mock1):
        self.assertEqual(restart(), 'Manager is going to restart now')

    @patch('wazuh.manager.exists', return_value=False)
    def test_restart_ko_socket(self, mock1):
        with self.assertRaises(WazuhException) as cm:
            restart()

        self.assertEqual(cm.exception.code, 1901)