# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

import os

from wazuh.core import common

API_PATH = os.path.join(common.WAZUH_PATH, 'api')
CONFIG_PATH = os.path.join(API_PATH, 'configuration')
CONFIG_FILE_PATH = os.path.join(CONFIG_PATH, 'api.yaml')
RELATIVE_CONFIG_FILE_PATH = os.path.relpath(CONFIG_FILE_PATH, common.WAZUH_PATH)
SECURITY_PATH = os.path.join(CONFIG_PATH, 'security')
SECURITY_CONFIG_PATH = os.path.join(SECURITY_PATH, 'security.yaml')
RELATIVE_SECURITY_PATH = os.path.relpath(SECURITY_PATH, common.WAZUH_PATH)
BASE_LOG_PATH = os.path.join(common.WAZUH_PATH, 'logs')
API_LOG_PATH = os.path.join(BASE_LOG_PATH, 'api')
COMMS_API_LOG_PATH = os.path.join(BASE_LOG_PATH, 'comms_api')
API_SSL_PATH = os.path.join(CONFIG_PATH, 'ssl')
INSTALLATION_UID_PATH = os.path.join(SECURITY_PATH, 'installation_uid')
INSTALLATION_UID_KEY = 'installation_uid'
UPDATE_INFORMATION_KEY = 'update_information'
