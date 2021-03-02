import os
import socket


def check(result):
    if result == 0:
        return 0
    else:
        return 1


def get_master_health():
    os.system("/var/ossec/bin/agent_control -ls > /tmp/output.txt")
    os.system("/var/ossec/bin/wazuh-control status > /tmp/daemons.txt")
    check0 = check(os.system("diff -q /tmp/output.txt /configuration_files/healthcheck/agent_control_check.txt"))
    check1 = check(os.system("diff -q /tmp/daemons.txt /configuration_files/healthcheck/daemons_check.txt"))
    check2 = check(os.system("grep -qs 'Listening on ' /var/ossec/logs/api.log"))
    return check0 or check1 or check2


def get_worker_health():
    os.system("/var/ossec/bin/wazuh-control status > /tmp/daemons.txt")
    check0 = check(os.system("diff -q /tmp/daemons.txt /configuration_files/healthcheck/daemons_check.txt"))
    check1 = check(os.system("grep -qs 'Listening on ' /var/ossec/logs/api.log"))
    return check0 or check1


def get_manager_health_base():
    return get_master_health() if socket.gethostname() == 'wazuh-master' else get_worker_health()


if __name__ == "__main__":
    exit(get_manager_health_base())
