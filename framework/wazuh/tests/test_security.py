#!/usr/bin/env python
# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import os
import re
import sqlite3
from unittest.mock import patch, mock_open

import pytest
import requests
from freezegun import freeze_time

import sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../..'))

with patch('wazuh.common.ossec_uid'):
    with patch('wazuh.common.ossec_gid'):
        from wazuh import common
        from wazuh.agent import Agent
        from wazuh.exception import WazuhException
        from wazuh.utils import WazuhVersion

from pwd import getpwnam
from grp import getgrnam

# all necessary params

test_data_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')


