from os import system, WEXITSTATUS
import socket

from base_healthcheck import get_manager_health_base

if __name__ == "__main__":
    # Workers are not needed in this test, so the exit code is set to 0 (healthy).
    # os.system can return 256 (wait status), so WEXITSTATUS translate it to 'exit' status.
    exit(WEXITSTATUS(system(
        "grep -q 'wazuh-modulesd:vulnerability-detector: INFO: (5471): Finished vulnerability assessment for agent '\\''001'\\''' /var/ossec/logs/ossec.log"))
         or get_manager_health_base()) if socket.gethostname() == 'wazuh-master' else exit(0)
