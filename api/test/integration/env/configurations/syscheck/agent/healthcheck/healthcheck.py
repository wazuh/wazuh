import os
import sys

sys.path.append('/tools')

from healthcheck_utils import check, get_agent_health_base

if __name__ == '__main__':
    exit(
        check(
            os.system(
                "grep -q 'syscheckd: INFO: (6009): File integrity monitoring scan ended.' /var/ossec/logs/ossec.log"
            )
        )
        or get_agent_health_base()
    )
