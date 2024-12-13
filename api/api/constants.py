# Copyright (C) 2015, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2
from wazuh.core import common

CERTS_PATH = common.WAZUH_ETC / 'certs'
SECURITY_PATH = common.WAZUH_ETC / 'api' / 'configuration' / 'security'
SECURITY_CONFIG_PATH = SECURITY_PATH / 'security.yaml'

INSTALLATION_UID_PATH = common.WAZUH_LIB / 'installation_uid'
INSTALLATION_UID_KEY = 'installation_uid'
UPDATE_INFORMATION_KEY = 'update_information'

API_KEY_PATH = CERTS_PATH / 'api.key'
API_CERT_PATH = CERTS_PATH / 'api.crt'
