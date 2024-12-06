# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from wazuh.core import common

API = 'api'
API_PATH = common.WAZUH_SHARE / API
CONFIG_PATH = common.WAZUH_ETC / API / 'configuration'
CONFIG_FILE_PATH = CONFIG_PATH / 'api.yaml'
SECURITY_PATH = CONFIG_PATH / 'security'
SECURITY_CONFIG_PATH = SECURITY_PATH / 'security.yaml'

INSTALLATION_UID_PATH = common.WAZUH_LIB / 'installation_uid'
INSTALLATION_UID_KEY = 'installation_uid'
UPDATE_INFORMATION_KEY = 'update_information'

API_SSL_PATH = CONFIG_PATH / 'ssl'
API_CERT_PATH = API_SSL_PATH / 'server.crt'
API_KEY_PATH = API_SSL_PATH / 'server.key'
