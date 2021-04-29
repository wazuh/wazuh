import os
import sys

sys.path.append('/tools')

from healthcheck_utils import get_agent_health_base

try:
    agent_old = sys.argv[1]
except IndexError:
    agent_old = False

wazuh_log_file = '/var/ossec/logs/wazuh.log' if not agent_old else '/var/ossec/logs/ossec.log'

if __name__ == "__main__":
    exit(os.system(
        f"grep -q 'sca: INFO: Security Configuration Assessment scan finished.' {wazuh_log_file}")
         or get_agent_health_base(agent_old=agent_old))
