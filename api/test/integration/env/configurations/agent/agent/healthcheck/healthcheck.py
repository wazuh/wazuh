import os
import sys

sys.path.append('/tools')

from healthcheck_utils import get_agent_health_base


def get_health():
    stats_files = ['/var/ossec/var/run/wazuh-logcollector.state']
    if all(os.path.exists(file) and os.path.getsize(file) > 0 for file in stats_files):
        return 0
    else:
        return 1


if __name__ == '__main__':
    exit(get_health() or get_agent_health_base())
