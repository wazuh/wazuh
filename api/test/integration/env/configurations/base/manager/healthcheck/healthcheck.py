import os
import socket


def check(result):
    if "differ" in result:
        return 1
    else:
        return 0


def get_master_health():
    os.system("/var/ossec/bin/agent_control -ls > /tmp/output.txt")
    os.system("/var/ossec/bin/ossec-control status > /tmp/daemons.txt")
    check1 = check(os.popen("diff -q /tmp/output.txt /configuration_files/healthcheck/agent_control_check.txt").read())
    check2 = check(os.popen("diff -q /tmp/daemons.txt /configuration_files/healthcheck/master_daemons_check.txt").read())
    check3 = 0 if os.system("grep -qs 'Listening on ' /var/ossec/logs/api.log") == 0 else 1
    return check1 or check2 or check3


def get_manager_health():
    os.system("/var/ossec/bin/ossec-control status > /tmp/daemons.txt")
    check1 = check(os.popen("diff -q /tmp/daemons.txt /configuration_files/healthcheck/master_daemons_check.txt").read())
    check2 = 0 if os.system("grep -qs 'Listening on ' /var/ossec/logs/api.log") == 0 else 1
    return check1 or check2


if __name__ == "__main__":
    exit(get_master_health()) if socket.gethostname() == 'wazuh-master' else exit(get_manager_health())
