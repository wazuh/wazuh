import sys
import os

from . import WAZUH_PATH


if sys.platform == 'win32':
    pass
else:
    CONF_PATH = os.path.join(WAZUH_PATH, 'etc')
    WAZUH_CONF_PATH = os.path.join(CONF_PATH, 'ossec.conf')

CUSTOM_RULES_PATH = os.path.join(CONF_PATH, 'rules')