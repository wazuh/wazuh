import os
import socket
import sys

sys.path.append('/tools')

from healthcheck_utils import get_manager_health_base, check

if __name__ == "__main__":
    # Workers are not needed in this test, so the exit code is set to 0 (healthy).
    exit(get_manager_health_base()) if socket.gethostname() == 'wazuh-master' else exit(0)
