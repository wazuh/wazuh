#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import sys
from unittest import TestCase

sys.path.append('../')

from wazuh import WazuhException
from wazuh.manager import upload_file


class TestManager(TestCase):

    def test_upload_file(self):
        # rules
        result = upload_file('./data/test_rules.xml', '.data')
        # decoders
        result = upload_file('./data/test_decoders.xml', '.data')
        # CDB lists
        result = upload_file('./data/test_rules', '.data')
