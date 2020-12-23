import os
import re
from datetime import datetime, timedelta

output_code_ciscat_scan = os.system(
    "grep -q 'wazuh-modulesd:ciscat: INFO: Scan finished successfully.' /var/ossec/logs/ossec.log")
output_code_ciscat_evaluation = os.system(
    "grep -q 'wazuh-modulesd:ciscat: INFO: Evaluation finished.' /var/ossec/logs/ossec.log")
output_code_sysc = os.system(
    "grep -q 'wazuh-modulesd:syscollector: INFO: Evaluation finished.' /var/ossec/logs/ossec.log")

if output_code_ciscat_scan == 0 and output_code_ciscat_evaluation == 0 and output_code_sysc == 0:
    exit(0)
else:
    # Check if the last ciscat evaluation started and did not finish
    output_ciscat_start = os.popen(
        "grep 'wazuh-modulesd:ciscat: INFO: Starting evaluation.' /var/ossec/logs/ossec.log").read().splitlines()
    last_ciscat_start = output_ciscat_start[len(output_ciscat_start) - 1]

    timestamp_last_ciscat_start = datetime.strptime(last_ciscat_start[:19], '%Y/%m/%d %H:%M:%S')

    # If the last ciscat evaluation is taking more than 150 seconds,
    # restart the daemon so a new ciscat evaluation starts
    if (datetime.now() - timestamp_last_ciscat_start) >= timedelta(seconds=150):
        # Kill the old wazuh-modulesd daemon
        old_modulesd_pidfile = os.popen(
            "ls /var/ossec/var/run/ | grep wazuh-modulesd-").read()
        old_modulesd_pid = re.search(r'(\d+).pid$', old_modulesd_pidfile).group(1)
        output_code_kill_modulesd = os.system(
            "kill {}".format(old_modulesd_pid))

        if output_code_kill_modulesd == 0:
            # Start wazuh-modulesd daemon
            os.system("/var/ossec/bin/wazuh-modulesd")

    exit(1)
