import os
import sys

sys.path.append('/tools')

from healthcheck_utils import get_agent_health_base, check

if __name__ == "__main__":
    exit(check(any([
        get_agent_health_base(),
        os.system("grep -q 'sca.*: INFO: Security Configuration Assessment scan finished.' /var/ossec/logs/ossec.log")
    ])))
