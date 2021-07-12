import os
import sys

sys.path.append('/tools')

from healthcheck_utils import get_agent_health_base

try:
    agent_old = sys.argv[1]
except IndexError:
    agent_old = False

wazuh_log_file = '/var/ossec/logs/wazuh.log' if not agent_old else '/var/ossec/logs/ossec.log'


def get_health():
    output = os.system(f"grep -q 'wazuh-modulesd:syscollector: INFO: Evaluation finished.' {wazuh_log_file}")

    if output == 0:
        return 0
    else:
        return 1


if __name__ == "__main__":
    exit(get_health() or get_agent_health_base(agent_old=agent_old))
