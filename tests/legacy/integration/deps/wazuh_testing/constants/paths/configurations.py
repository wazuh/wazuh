# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import sys

from . import WAZUH_PATH


if sys.platform == 'win32':
    WAZUH_CONF_PATH = os.path.join(WAZUH_PATH, 'ossec.conf')
else:
    CONF_PATH = os.path.join(WAZUH_PATH, 'etc')
    WAZUH_CONF_PATH = os.path.join(CONF_PATH, 'ossec.conf')

CUSTOM_RULES_PATH = os.path.join(CONF_PATH, 'rules')
