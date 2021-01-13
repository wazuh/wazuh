import os
import socket


def check(result):
    if result == 0:
        return 0
    else:
        return 1


def get_master_health():
    os.system("/var/ossec/bin/agent_control -ls > /tmp/output.txt")
    check0 = check(os.system("diff -q /tmp/output.txt /configuration_files/healthcheck/agent_control_check.txt"))
    check1 = check(os.system("grep -q 'syscheckd: INFO: (6009): File integrity monitoring scan ended.' /var/ossec/logs/ossec.log"))
    check2 = check(os.system("grep -qs 'Listening on ' /var/ossec/logs/api.log"))
    return check0 or check1 or check2


if __name__ == "__main__":
    # Workers are not needed in this test, so the exit code is set to 0 (healthy).
    exit(get_master_health()) if socket.gethostname() == 'wazuh-master' else exit(0)
