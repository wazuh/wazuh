import os
import sys

sys.path.append('/tools')

from healthcheck_utils import get_agent_health_base, check

if __name__ == "__main__":
    base_health = get_agent_health_base()

    # The last scan must have ended: a running one adds results back after the DELETE stages.
    # Read after the base check, whose 30 second wait gives the restarted agent time to start its scan.
    last_scan_event = os.popen("grep -E 'rootcheck: INFO: (Starting|Ending) rootcheck scan' "
                               "/var/ossec/logs/ossec.log | tail -1").read()

    exit(check(any([
        base_health,
        'Ending rootcheck scan' not in last_scan_event
    ])))
