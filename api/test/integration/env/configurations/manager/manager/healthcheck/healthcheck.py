import os
import socket
import sys
sys.path.append('/tools')

from healthcheck_utils import check


def get_master_health():
    os.system("/var/ossec/bin/wazuh-control status > /tmp/daemons.txt")
    check0 = check(os.system("diff -q /tmp/daemons.txt /tmp/healthcheck/master_daemons_check.txt"))
    check1 = check(os.system("grep -qs 'Listening on ' /var/ossec/logs/api.log"))
    return check0 or check1


if __name__ == "__main__":
    # Workers are not needed in this test, so the exit code is set to 0 (healthy).
    exit(get_master_health()) if socket.gethostname() == 'wazuh-master' else exit(0)
