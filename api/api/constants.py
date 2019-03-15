# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

from wazuh import common

API_PATH = os.path.join(common.ossec_path, 'api')
CONFIG_PATH = os.path.join(API_PATH, 'configuration')
CONFIG_FILE_PATH = os.path.join(CONFIG_PATH, 'api.yml')
SECURITY_PATH = os.path.join(CONFIG_PATH, 'security')
