import os
import socket
import sys

sys.path.append('/tools')

from healthcheck_utils import check, get_api_health


def get_master_health():
    os.system("/var/ossec/bin/wazuh-control status > /tmp_volume/daemons.txt")
    check0 = check(os.system("diff -q /tmp_volume/daemons.txt /tmp_volume/healthcheck/daemons_check.txt"))
    check1 = get_api_health()
    return check0 or check1


if __name__ == "__main__":
    # Workers are not needed in this test, so the exit code is set to 0 (healthy).
    exit(get_master_health()) if socket.gethostname() == 'wazuh-master' else exit(0)
