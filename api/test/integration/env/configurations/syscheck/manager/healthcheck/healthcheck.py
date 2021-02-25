import os
import socket

from base_healthcheck import get_manager_health_base

if __name__ == "__main__":
    # Workers are not needed in this test, so the exit code is set to 0 (healthy).
    exit(os.system(
        "grep -q 'wazuh-syscheckd: INFO: (6009): File integrity monitoring scan ended.' /var/ossec/logs/ossec.log")
         or get_manager_health_base()) if socket.gethostname() == 'wazuh-master' else exit(0)
