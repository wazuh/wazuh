# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import sys

from . import WAZUH_PATH


if sys.platform == 'win32':
    OSSEC_LOG_PATH = os.path.join(WAZUH_PATH, 'ossec.log')
else:
    OSSEC_LOG_PATH = os.path.join(WAZUH_PATH, 'logs', 'ossec.log')

BASE_LOGS_PATH = os.path.join(WAZUH_PATH, 'logs')

ALERTS_LOG_PATH = os.path.join(BASE_LOGS_PATH, 'alerts', 'alerts.log')
ALERTS_JSON_PATH = os.path.join(BASE_LOGS_PATH, 'alerts', 'alerts.json')
