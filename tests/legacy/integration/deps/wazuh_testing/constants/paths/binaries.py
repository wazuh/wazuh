# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

from . import WAZUH_PATH


BIN_PATH = os.path.join(WAZUH_PATH, 'bin')
WAZUH_CONTROL_PATH = os.path.join(BIN_PATH, 'wazuh-control')
