import platform
import subprocess
from pathlib import Path

from ..constants.paths import WAZUH_PATH


def get_version():

    if platform.system() in ['Windows', 'win32']:
        with open(Path(WAZUH_PATH, 'VERSION'), 'r') as f:
            version = f.read()
            return version[:version.rfind('\n')]

    else:  # Linux, sunos5, darwin, aix...
        return subprocess.check_output([
            f"{WAZUH_PATH}/bin/wazuh-control", "info", "-v"
        ], stderr=subprocess.PIPE).decode('utf-8').rstrip()


def get_service():
    if platform.system() in ['Windows', 'win32']:
        return 'wazuh-agent'

    else:  # Linux, sunos5, darwin, aix...
        service = subprocess.check_output([
            f"{WAZUH_PATH}/bin/wazuh-control", "info", "-t"
        ], stderr=subprocess.PIPE).decode('utf-8').strip()

    return 'wazuh-manager' if service == 'server' else 'wazuh-agent'
